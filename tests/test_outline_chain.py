"""Regression tests: run on any Unix Python 3.10+ host, without root/Docker."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "outline_chain.py"
spec = importlib.util.spec_from_file_location("outline_chain", SOURCE)
oc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oc)


def cfg(enabled=False):
    return {"enabled": enabled, "ready": True, "container": "shadowbox", "probe": "198.18.254.1",
            "interface": "eth0", "expected_exit": None,
            "target": {"ip": "203.0.113.9", "port": 5357, "host": "203.0.113.9", "cipher": "aes-256-gcm"}}


def original():
    return {"Id": "abcdef0123456789", "Name": "/shadowbox", "Image": "sha256:original",
            "Config": {"Image": "quay.io/outline/shadowbox:stable", "Env": ["SECRET=keep-this"],
                       "Cmd": ["/cmd.sh"], "Labels": {"custom": "keep", "com.centurylinklabs.watchtower.enable": "true"}},
            "HostConfig": {"NetworkMode": "host", "RestartPolicy": {"Name": "always"},
                           "Binds": ["/opt/outline:/opt/outline"], "LogConfig": {"Type": "local"}},
            "State": {"Running": True}}


class Keys(unittest.TestCase):
    def encoded(self, text):
        return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")

    def test_outline_sip002(self):
        token = self.encoded("chacha20-ietf-poly1305:example-secret")
        result = oc.parse_key(f"ss://{token}@203.0.113.9:5357/?outline=1#VM%20B")
        self.assertEqual(result["port"], 5357)
        self.assertEqual(result["ip"], "203.0.113.9")
        self.assertNotIn("?", result["uri"])
        self.assertNotIn("secret", json.dumps(oc.public_target(result)))

    def test_legacy_whole_key(self):
        key = "ss://" + self.encoded("aes-256-gcm:password@203.0.113.7:443")
        self.assertEqual(oc.parse_key(key)["port"], 443)

    def test_plain_percent_encoded_password(self):
        parsed = oc.parse_key("ss://aes-256-gcm:hello%40world%3Aother@203.0.113.7:443")
        credentials = parsed["uri"].split("//")[1].split("@")[0]
        self.assertEqual(oc.decode64(credentials), "aes-256-gcm:hello@world:other")

    def test_domain_is_pinned_to_ipv4(self):
        token = self.encoded("aes-128-gcm:secret")
        def resolve(*args):
            return [(None, None, None, None, ("203.0.113.10", 443))]
        result = oc.parse_key(f"ss://{token}@vm.example:443", resolver=resolve)
        self.assertEqual(result["host"], "vm.example")
        self.assertIn("@203.0.113.10:443", result["uri"])

    def test_reject_unsupported_and_malformed(self):
        keys = ["ssconf://secret.example/key", "ss://garbage", "ss://aes-256-gcm:@203.0.113.9:443",
                "ss://aes-256-gcm:secret@203.0.113.9:99999", "ss://rc4:secret@203.0.113.9:443",
                "ss://aes-256-gcm:secret@[2001:db8::1]:443",
                "ss://aes-256-gcm:secret@203.0.113.9:443/?prefix=abc",
                "ss://aes-256-gcm:secret@203.0.113.9:443/?plugin=abc",
                "ss://" + self.encoded("aes-256-gcm:secret@203.0.113.9:443") + "?plugin=abc"]
        for key in keys:
            with self.subTest(key=key), self.assertRaises(oc.Error) as raised:
                oc.parse_key(key)
            self.assertNotIn("secret", str(raised.exception))

    def test_redaction(self):
        self.assertEqual(oc.scrub('proxy ss://secret@server:443/ failed'), 'proxy [REDACTED] failed')


class NetworkPolicy(unittest.TestCase):
    def test_guard_is_postrouting(self):
        rules = oc.table_rules(cfg())
        post = next(row for row in rules if row[2] == "OC_POST")
        self.assertEqual(post[1], "mangle")
        self.assertEqual(post[3][-2:], ["-j", "DROP"])
        self.assertIn(oc.SLICE, post[3])
        self.assertNotIn("--mark", post[3])  # protection does not depend on the mark surviving
        self.assertIn(("iptables", "mangle", "POSTROUTING", "OC_POST"), oc.HOOKS)
        self.assertNotIn(("iptables", "filter", "OUTPUT", "OC_POST"), oc.HOOKS)

    def test_only_original_connections_in_stable_group(self):
        mark = oc.table_rules(cfg())[0][3]
        self.assertEqual(mark[mark.index("--path") + 1], "outlinechain.slice")
        self.assertEqual(mark[mark.index("--ctdir") + 1], "ORIGINAL")
        self.assertEqual(mark[-1], oc.MARK)

    def test_ipv6_blocked_for_outline_only(self):
        v6 = oc.table_rules(cfg())[2]
        self.assertEqual(v6[0], "ip6tables")
        self.assertIn(oc.SLICE, v6[3])
        self.assertEqual(v6[3][-1], "REJECT")

    def test_route_failure_does_not_attach_hooks(self):
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, "1.1.1.1 via gateway dev eth0\n", "")
        with patch.object(oc.Path, "is_dir", return_value=True), patch.object(oc, "ensure_ip_rule"), patch.object(oc, "run", side_effect=run):
            with self.assertRaises(oc.Error):
                oc.attach(cfg())
        self.assertFalse(any(args[0] in ("iptables", "ip6tables") for args in calls))

    def test_guards_activated_before_marking(self):
        order = []
        def ensure(tool, table, chain, rule, **kwargs):
            if kwargs.get("insert"):
                order.append((chain, rule[-1]))
        with patch.object(oc.Path, "is_dir", return_value=True), patch.object(oc, "ensure_ip_rule"), \
             patch.object(oc, "run", return_value=subprocess.CompletedProcess([], 0, "dev ocss0", "")), \
             patch.object(oc, "ensure_rule", side_effect=ensure):
            oc.attach(cfg())
        self.assertEqual(order[-1], ("OUTPUT", "OC_ROUTE"))
        self.assertEqual(order[0], ("POSTROUTING", "OC_POST"))

    def test_parse_trace_and_expected_ip(self):
        with patch.object(oc, "run", return_value=subprocess.CompletedProcess([], 0, "fl=abc\nip=203.0.113.10\n", "")):
            self.assertEqual(oc.probe(cfg()), "203.0.113.10")
            state = cfg()
            state["expected_exit"] = "203.0.113.11"
            with self.assertRaises(oc.Error):
                oc.probe(state)
        with self.assertRaises(oc.Error):
            oc.trace_ip("an HTML error page")


class Transactions(unittest.TestCase):
    def test_managed_clone_preserves_settings_and_mounts(self):
        before = original()
        cloned = oc.managed_payload(before)
        self.assertEqual(cloned["Env"], before["Config"]["Env"])
        self.assertEqual(cloned["HostConfig"]["Binds"], before["HostConfig"]["Binds"])
        self.assertEqual(cloned["HostConfig"]["LogConfig"], {"Type": "local"})
        self.assertEqual(cloned["HostConfig"]["CgroupParent"], oc.SLICE)
        self.assertEqual(cloned["HostConfig"]["RestartPolicy"]["Name"], "no")
        self.assertEqual(cloned["Labels"]["com.centurylinklabs.watchtower.enable"], "false")
        self.assertEqual(cloned["Image"], before["Image"])
        self.assertNotIn(oc.LABEL, before["Config"]["Labels"])

    def test_failed_recreate_restores_old_container(self):
        calls = []
        state = cfg()
        def api(method, path, data=None, **kw):
            calls.append((method, path, data))
            if path.startswith("/containers/create"):
                raise oc.Error("create failed")
        with patch.object(oc, "api", side_effect=api), patch.object(oc, "save"), \
             patch.object(oc, "stop_container"), patch.object(oc, "start_container") as start:
            with self.assertRaises(oc.Error):
                oc.replace_container(state, original(), {})
        self.assertNotIn("transition", state)
        start.assert_called_once_with(original()["Id"])
        self.assertEqual(calls[-1][2], {"RestartPolicy": {"Name": "always"}})
        self.assertTrue(any("rename?name=shadowbox" in c[1] for c in calls))

    def test_successful_recreate_never_deletes_volumes(self):
        calls = []
        def api(method, path, data=None, **kw):
            calls.append((method, path))
            return {"Id": "new-container"} if path.startswith("/containers/create") else None
        with patch.object(oc, "api", side_effect=api), patch.object(oc, "save"), \
             patch.object(oc, "stop_container"), patch.object(oc, "start_container"), \
             patch.object(oc, "inspect", return_value={"State": {"Running": True}}), \
             patch.object(oc, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            oc.replace_container(cfg(), original(), {})
        self.assertIn(("DELETE", "/containers/abcdef0123456789"), calls)
        self.assertFalse(any("v=true" in path for _, path in calls))

    def test_failed_activation_restores_direct_mode(self):
        state = cfg(False)
        with patch.object(oc, "run"), patch.object(oc, "require_managed"), \
             patch.object(oc, "ensure_tunnel"), patch.object(oc, "test_upstream", side_effect=oc.Error("unreachable")), \
             patch.object(oc, "detach") as detach, patch.object(oc, "set_dns") as dns, patch.object(oc, "stop_tunnel") as stop:
            with self.assertRaises(oc.Error):
                oc.toggle(state, True)
        detach.assert_called_once()
        dns.assert_called_once_with(state, False)
        stop.assert_called_once()
        self.assertFalse(state["enabled"])

    def test_failed_recheck_while_on_does_not_fail_open(self):
        with patch.object(oc, "run"), patch.object(oc, "require_managed"), \
             patch.object(oc, "ensure_tunnel"), patch.object(oc, "test_upstream", side_effect=oc.Error("unreachable")), \
             patch.object(oc, "detach") as detach, patch.object(oc, "stop_tunnel") as stop:
            with self.assertRaises(oc.Error):
                oc.toggle(cfg(True), True)
        detach.assert_not_called()
        stop.assert_not_called()

    def test_off_mode_test_cleans_up_even_on_tunnel_start_failure(self):
        with patch.object(oc, "ensure_tunnel", side_effect=oc.Error("startup failed")), patch.object(oc, "stop_tunnel") as stop:
            with self.assertRaises(oc.Error):
                oc.test_command(cfg())
        stop.assert_called_once()

    def test_bad_target_rolls_back_secret_without_disabling_on_mode(self):
        state = cfg(True)
        previous = copy.deepcopy(state)
        target = oc.parse_key("ss://aes-256-gcm:password@203.0.113.20:443")
        class Args:
            expected_exit_ip = None
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "proxy.yml"
            secret.write_text("old secret configuration\n")
            with patch.object(oc, "PROXY", secret), patch.object(oc, "TARGET_JOURNAL", Path(directory)/"journal"), patch.object(oc, "read_target", return_value=target), \
                 patch.object(oc, "run", return_value=subprocess.CompletedProcess([], 0, "[]", "")), \
                 patch.object(oc, "ensure_tunnel"), patch.object(oc, "save") as save, \
                 patch.object(oc, "test_upstream", side_effect=oc.Error("new key fails")), patch.object(oc, "stop_tunnel") as stop:
                with self.assertRaises(oc.Error):
                    oc.set_target(state, Args())
            self.assertEqual(secret.read_text(), "old secret configuration\n")
            self.assertEqual(save.call_args.args[0], previous)
            stop.assert_not_called()


class FilesAndUnits(unittest.TestCase):
    def test_interrupted_target_update_restores_private_key_and_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = root / "journal"
            proxy = root / "proxy"
            journal.write_text(json.dumps({"config": cfg(True), "proxy": "old-private-key"}))
            proxy.write_text("uncommitted-new-key")
            with patch.object(oc, "TARGET_JOURNAL", journal), patch.object(oc, "PROXY", proxy), patch.object(oc, "save") as save:
                self.assertTrue(oc.rollback_target_journal())
            self.assertEqual(proxy.read_text(), "old-private-key")
            self.assertEqual(proxy.stat().st_mode & 0o777, 0o600)
            self.assertFalse(journal.exists())
            self.assertTrue(save.call_args.args[0]["enabled"])

    def test_boot_protection_precedes_container_start_and_stop_precedes_cleanup(self):
        events = []
        def action(name):
            return lambda *a, **k: events.append(name)
        class ImmediateStop:
            def wait(self, timeout):
                return True
            def set(self):
                pass
        with patch.object(oc, "load", return_value=cfg(True)), \
             patch.object(oc, "require_managed", return_value=original()), \
             patch.object(oc.threading, "Event", return_value=ImmediateStop()), \
             patch.object(oc.signal, "signal"), \
             patch.object(oc, "ensure_tunnel", side_effect=action("tunnel")), \
             patch.object(oc, "attach", side_effect=action("guard")), \
             patch.object(oc, "start_container", side_effect=action("start")), \
             patch.object(oc, "set_dns", side_effect=action("dns")), \
             patch.object(oc, "notify_ready", side_effect=action("ready")), \
             patch.object(oc, "stop_container", side_effect=action("stop")), \
             patch.object(oc, "detach", side_effect=action("detach")), \
             patch.object(oc, "stop_tunnel", side_effect=action("stop_tunnel")):
            oc.serve()
        self.assertLess(events.index("guard"), events.index("start"))
        self.assertLess(events.index("stop"), events.index("detach"))
        self.assertLess(events.index("detach"), events.index("stop_tunnel"))

    def test_container_udp_failure_is_not_reported_as_success(self):
        with patch.object(oc, "require_managed"), patch.object(oc, "probe", return_value="203.0.113.10"), \
             patch.object(oc, "docker_exec", return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaises(oc.Error):
                oc.test_container(cfg(True), "203.0.113.10")

    def test_private_atomic_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            oc.atomic(path, "private")
            self.assertEqual(path.read_text(), "private")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            oc.atomic(path, "replacement")
            self.assertEqual(path.read_text(), "replacement")
            self.assertEqual(len(list(Path(directory).iterdir())), 1)

    def test_systemd_boot_before_container_and_keep_tunnel_independent(self):
        units = oc.unit_texts()
        controller = units[oc.SERVICE]
        tunnel = units[oc.TUN_SERVICE]
        self.assertIn("Type=notify", controller)
        self.assertIn("outlinechain.slice", controller)
        self.assertIn("WantedBy=multi-user.target docker.service", controller)
        self.assertIn("PartOf=docker.service", controller)
        self.assertIn("Restart=on-failure", tunnel)
        self.assertNotIn("ExecStop", tunnel)  # a proxy crash must not remove the fail-closed route
        self.assertNotIn("Before=outline-chain.service", tunnel)  # avoid synchronous systemctl dependency deadlock

    def test_help_without_root(self):
        result = subprocess.run([os.sys.executable, str(SOURCE), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("set-target", result.stdout)
        self.assertNotIn("==SUPPRESS==", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
