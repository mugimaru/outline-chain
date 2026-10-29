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


def amn_cfg(enabled=False, ready=True):
    state = cfg(enabled)
    state["amnezia"] = {"subnet": "172.31.250.0/24", "gateway": "172.31.250.1",
                        "containers": {"amnezia-awg": {"exclude": ["172.29.172.0/24"], "ready": ready}}}
    return state


def amn_original():
    return {"Id": "fedcba9876543210", "Name": "/amnezia-awg", "Image": "sha256:awg",
            "Config": {"Image": "amnezia-awg", "Env": ["AWG=1"], "Labels": {}},
            "HostConfig": {"NetworkMode": "default", "RestartPolicy": {"Name": "always"}, "Privileged": True,
                           "PortBindings": {"51820/udp": [{"HostPort": "51820"}]}},
            "NetworkSettings": {"Networks": {
                "bridge": {"IPAddress": "172.17.0.2"},
                "amnezia-dns-net": {"IPAMConfig": {"IPv4Address": "172.29.172.2"},
                                    "Aliases": ["fedcba987654", "awg"]}}},
            "State": {"Running": True, "Pid": 4242}}


def amn_managed():
    item = amn_original()
    payload = oc.amnezia_payload(item)
    item["Config"]["Labels"] = payload["Labels"]
    item["HostConfig"] = payload["HostConfig"]
    item["NetworkSettings"]["Networks"] = {oc.AMN_NET: {}, "amnezia-dns-net": {}}
    return item


class Amnezia(unittest.TestCase):
    def test_guard_is_postrouting_by_source_without_mark(self):
        rules = oc.amnezia_rules(amn_cfg())
        post = [r for r in rules if r[2] == "OC_AMN_POST"]
        self.assertEqual(post[-1][3][-2:], ["-j", "DROP"])
        self.assertIn("172.31.250.0/24", post[-1][3])
        self.assertNotIn("--mark", post[-1][3])
        self.assertIn(("iptables", "mangle", "POSTROUTING", "OC_AMN_POST"), oc.HOOKS)

    def test_mark_only_original_forwarded_traffic_from_managed_bridge(self):
        mark = [r for r in oc.amnezia_rules(amn_cfg()) if r[2] == "OC_AMN_ROUTE"][-1][3]
        self.assertEqual(mark[mark.index("-i") + 1], oc.AMN_BRIDGE)
        self.assertEqual(mark[mark.index("--ctdir") + 1], "ORIGINAL")
        self.assertEqual(mark[-1], oc.MARK)
        self.assertIn(("iptables", "mangle", "PREROUTING", "OC_AMN_ROUTE"), oc.HOOKS)

    def test_bridge_exclusions_precede_actions(self):
        for chain in oc.AMN_CHAINS:
            rules = [r[3] for r in oc.amnezia_rules(amn_cfg()) if r[2] == chain]
            self.assertEqual([r[1] for r in rules[:-1]], ["172.29.172.0/24", "172.31.250.0/24"])
            self.assertTrue(all(r[-1] == "RETURN" for r in rules[:-1]))
        self.assertEqual(oc.amnezia_rules(cfg()), [])

    def test_chain_refresh_is_one_restore_transaction(self):
        with patch.object(oc, "run") as run:
            oc.amnezia_chains(amn_cfg())
        args, kwargs = run.call_args
        self.assertEqual(args[0][:1], ["iptables-restore"])
        self.assertIn("--noflush", args[0])
        self.assertTrue(kwargs["input"].startswith("*mangle\n:OC_AMN_ROUTE - [0:0]\n:OC_AMN_POST - [0:0]\n"))
        self.assertTrue(kwargs["input"].endswith("COMMIT\n"))

    def test_all_guards_hooked_before_any_marking(self):
        order = []
        def ensure(tool, table, chain, rule, **kwargs):
            if kwargs.get("insert"):
                order.append(rule[-1])
        with patch.object(oc.Path, "is_dir", return_value=True), patch.object(oc, "ensure_ip_rule"), \
             patch.object(oc, "run", return_value=subprocess.CompletedProcess([], 0, "dev ocss0", "")), \
             patch.object(oc, "ensure_rule", side_effect=ensure):
            oc.attach(amn_cfg(True))
        self.assertEqual(order[:3], ["OC_POST", "OC_V6", "OC_AMN_POST"])
        self.assertEqual(sorted(order[3:]), ["OC_AMN_ROUTE", "OC_ROUTE"])

    def test_payload_moves_to_managed_bridge_and_preserves_settings(self):
        before = amn_original()
        payload = oc.amnezia_payload(before)
        self.assertEqual(payload["Env"], ["AWG=1"])
        self.assertEqual(payload["Image"], "sha256:awg")
        self.assertEqual(payload["HostConfig"]["PortBindings"], before["HostConfig"]["PortBindings"])
        self.assertTrue(payload["HostConfig"]["Privileged"])
        self.assertEqual(payload["HostConfig"]["NetworkMode"], oc.AMN_NET)
        self.assertEqual(payload["HostConfig"]["RestartPolicy"]["Name"], "no")
        self.assertIn(oc.AMN_NET, payload["NetworkingConfig"]["EndpointsConfig"])
        self.assertTrue(oc.amnezia_managed(amn_managed()))
        self.assertFalse(oc.amnezia_managed(before))

    def test_extra_networks_keep_static_ip_and_drop_generated_alias(self):
        networks = oc.extra_networks(amn_original(), ())
        self.assertEqual(networks, [("amnezia-dns-net", {"IPAMConfig": {"IPv4Address": "172.29.172.2"},
                                                         "Aliases": ["awg"]})])

    def test_restore_payload_uses_original_primary_network(self):
        before = amn_original()
        before["HostConfig"]["NetworkMode"] = "amnezia-dns-net"
        payload = oc.original_payload(before)
        self.assertEqual(payload["HostConfig"]["NetworkMode"], "amnezia-dns-net")
        self.assertEqual(payload["NetworkingConfig"]["EndpointsConfig"]["amnezia-dns-net"]["IPAMConfig"],
                         {"IPv4Address": "172.29.172.2"})
        self.assertNotIn("NetworkingConfig", oc.original_payload(original()))  # Outline: host networking

    def test_networks_connected_before_start(self):
        events = []
        def api(method, path, data=None, **kw):
            events.append(path)
            return {"Id": "new-container"} if path.startswith("/containers/create") else None
        with patch.object(oc, "api", side_effect=api), patch.object(oc, "save"), \
             patch.object(oc, "stop_container"), patch.object(oc, "start_container", side_effect=lambda *a: events.append("start")), \
             patch.object(oc, "inspect", return_value={"State": {"Running": True}}):
            oc.replace_container(amn_cfg(), amn_original(), {}, name="amnezia-awg",
                                 networks=[("amnezia-dns-net", {})], ready=lambda _: True)
        self.assertLess(events.index("/networks/amnezia-dns-net/connect"), events.index("start"))
        self.assertIn("/containers/create?name=amnezia-awg", events)

    def test_default_route_outside_managed_bridge_is_refused(self):
        routes = json.dumps([{"dst": "default", "gateway": "172.29.172.1", "dev": "eth1"}])
        with patch.object(oc, "run", return_value=subprocess.CompletedProcess([], 0, routes, "")) as run:
            with self.assertRaises(oc.Error):
                oc.check_gateway(amn_cfg(), "amnezia-awg", amn_original())
        self.assertEqual(run.call_args.args[0][:4], ["nsenter", "-t", "4242", "-n"])

    def test_egress_test_runs_in_container_namespace(self):
        commands = []
        def run(args, **kwargs):
            commands.append(args)
            if "route" in args:
                return subprocess.CompletedProcess(args, 0, json.dumps([{"gateway": "172.31.250.1"}]), "")
            if args[4] == "curl":
                return subprocess.CompletedProcess(args, 0, "ip=203.0.113.10\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")  # no DNS answer
        with patch.object(oc, "inspect", return_value=amn_managed()), patch.object(oc, "run", side_effect=run):
            with self.assertRaises(oc.Error) as raised:
                oc.test_amnezia(amn_cfg(True), "amnezia-awg", "203.0.113.10")
        self.assertIn("UDP DNS", str(raised.exception))
        self.assertTrue(all(c[:4] == ["nsenter", "-t", "4242", "-n"] for c in commands))

    def test_supervisor_stops_unmanaged_container_only_while_on(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled), patch.object(oc, "inspect", return_value=amn_original()), \
                 patch.object(oc, "stop_container") as stop, patch.object(oc, "start_container") as start, \
                 patch("sys.stderr"):
                oc.supervise_amnezia(amn_cfg(enabled), {})
            self.assertEqual(stop.called, enabled)
            start.assert_not_called()

    def test_supervisor_ignores_uncommitted_and_starts_managed(self):
        stopped = amn_managed()
        stopped["State"]["Running"] = False
        with patch.object(oc, "inspect", side_effect=[stopped, amn_managed()]), \
             patch.object(oc, "start_container") as start, patch.object(oc, "check_gateway"):
            oc.supervise_amnezia(amn_cfg(True), {})
        start.assert_called_once_with("amnezia-awg")
        with patch.object(oc, "inspect") as inspect:
            self.assertEqual(oc.supervise_amnezia(amn_cfg(True, ready=False), {}), {})
        inspect.assert_not_called()

    def test_failed_add_forgets_container(self):
        state = cfg(False)
        state["amnezia"] = {"subnet": "172.31.250.0/24", "gateway": "172.31.250.1", "containers": {}}
        class Args:
            name = "amnezia-awg"
            subnet = oc.AMN_SUBNET
        with patch.object(oc, "inspect", return_value=amn_original()), patch.object(oc, "preflight_amnezia", return_value=[]), \
             patch.object(oc, "atomic"), patch.object(oc, "save"), \
             patch.object(oc, "replace_container", side_effect=oc.Error("create failed")):
            with self.assertRaises(oc.Error):
                oc.amnezia_add(state, Args())
        self.assertEqual(state["amnezia"]["containers"], {})

    def test_add_while_on_hooks_guards_before_replacing(self):
        state = amn_cfg(True)
        state["amnezia"]["containers"] = {}
        events = []
        class Args:
            name = "amnezia-awg"
            subnet = oc.AMN_SUBNET
        with patch.object(oc, "inspect", return_value=amn_original()), patch.object(oc, "preflight_amnezia", return_value=[]), \
             patch.object(oc, "atomic"), patch.object(oc, "save"), \
             patch.object(oc, "attach", side_effect=lambda *a: events.append("attach")), \
             patch.object(oc, "replace_container", side_effect=lambda *a, **k: events.append("replace")), \
             patch.object(oc, "test_upstream", return_value="203.0.113.10"), patch.object(oc, "test_amnezia"):
            oc.amnezia_add(state, Args())
        self.assertEqual(events, ["attach", "replace"])

    def test_unknown_name_lists_amnezia_containers(self):
        class Args:
            name = "amnezia-awg"
            subnet = oc.AMN_SUBNET
        rows = [{"Names": ["/amnezia-awg2"], "Image": "amnezia-awg2"}, {"Names": ["/hbbs"], "Image": "rustdesk"}]
        with patch.object(oc, "inspect", side_effect=oc.DockerError("missing", 404)), \
             patch.object(oc, "api", return_value=rows):
            with self.assertRaises(oc.Error) as raised:
                oc.amnezia_add(cfg(), Args())
        self.assertIn("Amnezia containers here: amnezia-awg2.", str(raised.exception))

    def test_recover_settles_registration(self):
        for kind, committed, expected in [("amnezia-add", True, True), ("amnezia-add", False, None),
                                          ("amnezia-remove", True, None), ("amnezia-remove", False, True)]:
            with self.subTest(kind=kind, committed=committed):
                state = amn_cfg(ready=False)
                oc.settle_amnezia(state, "amnezia-awg", kind, committed=committed)
                entry = state["amnezia"]["containers"].get("amnezia-awg")
                self.assertEqual(entry and entry["ready"], expected)


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
             patch.object(oc, "stop_tunnel", side_effect=action("stop_tunnel")), \
             patch.object(oc, "supervise_amnezia", side_effect=lambda *a: events.append("amnezia") or {}):
            oc.serve()
        self.assertLess(events.index("guard"), events.index("start"))
        self.assertLess(events.index("guard"), events.index("amnezia"))
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
