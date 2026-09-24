#!/usr/bin/env python3
"""Manage an Outline -> Shadowsocks chain on a local Ubuntu Docker host.

Python 3.10+, standard library only. Run --help before installation.
Network policy follows the tested OUTPUT mark / POSTROUTING guard design.
"""
from __future__ import annotations

import argparse
import base64
import copy
import fcntl
import getpass
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile

VERSION = "1.0.0"
ROOT = Path("/etc/outline-chain")
STATE = ROOT / "config.json"
BACKUP = ROOT / "original-container.json"
RESOLV = ROOT / "original-resolv.conf"
PROXY = ROOT / "proxy.yml"
TARGET_JOURNAL = ROOT / "target-update.json"
LIB = Path("/usr/local/lib/outline-chain")
BIN = Path("/usr/local/sbin/outline-chain")
UNITS = Path("/etc/systemd/system")
SLICE = "outlinechain.slice"
SERVICE = "outline-chain.service"
TUN_SERVICE = "outline-chain-tunnel.service"
LABEL = "io.outline-chain.managed"
TUN = "ocss0"
TABLE = 20877
MARK = "0x4f430001"
MARK_RULE = 20876
PROBE_RULE = 20877
CHAINS = ("OC_ROUTE", "OC_POST", "OC_V6")
TUN_VERSION = "2.7.0"
RELEASES = {
    "x86_64": ("amd64", "a612baa287a3b6de6221f74fd02b442a50888508227ecf51e1288a5ccbb77381"),
    "aarch64": ("arm64", "3931476c9cfa8fa236d23aeaf36767df0eb27cc11ecaab699faba57744450f49"),
}
DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]


class Error(Exception):
    pass


class DockerError(Error):
    def __init__(self, message, status):
        super().__init__(message)
        self.status = status


def scrub(text):
    return re.sub(r"ss(?:conf)?://[^\s\"']+", "[REDACTED]", str(text))


def run(args, *, check=True, input=None, timeout=60):
    env = os.environ.copy()
    env.pop("DOCKER_CONTEXT", None)
    env["LC_ALL"] = "C"
    try:
        result = subprocess.run([str(x) for x in args], input=input, text=True,
                                capture_output=True, timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Error(f"{args[0]} could not complete: {type(exc).__name__}") from None
    if check and result.returncode:
        detail = scrub(result.stderr or result.stdout).strip()[-1600:]
        raise Error(f"{args[0]} failed (exit {result.returncode}): {detail}")
    return result


def atomic(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".outline-chain-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save(cfg):
    atomic(STATE, json.dumps(cfg, indent=2) + "\n")


def rollback_target_journal():
    if TARGET_JOURNAL.exists():
        previous = json.loads(TARGET_JOURNAL.read_text())
        atomic(PROXY, previous["proxy"])
        save(previous["config"])
        TARGET_JOURNAL.unlink()
        return True
    return False


def load():
    if not STATE.exists():
        raise Error("Not installed. Run setup first.")
    return json.loads(STATE.read_text())


def decode64(value):
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4),
                                altchars=b"-_", validate=True).decode("utf-8")
    except (ValueError, UnicodeError):
        raise Error("Invalid base64 in the access key.") from None


def parse_key(key, resolver=None):
    """Normalize SIP002 and legacy whole-URI base64 keys; never expose a secret."""
    key = key.strip()
    if not key.startswith("ss://") or any(c.isspace() for c in key):
        raise Error("Use a plain ss:// access key, not ssconf:// or a sharing URL.")
    try:
        raw = key[5:].split("#", 1)[0]
        if "@" not in raw:
            encoded, separator, query_text = raw.partition("?")
            raw = decode64(encoded) + ("?" + query_text if separator else "")
        url = urllib.parse.urlsplit("ss://" + raw)
        query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
        if set(query) - {"outline"}:
            raise Error("Plugin, prefix, and other extended SS keys are unsupported.")
        if url.path not in ("", "/") or not url.hostname or not url.port:
            raise Error("The key must contain a server and port.")
        credentials = url.netloc.rsplit("@", 1)[0]
        credentials = urllib.parse.unquote(credentials)
        if ":" not in credentials:
            credentials = decode64(credentials)
        method, password = credentials.split(":", 1)
        if method not in {"chacha20-ietf-poly1305", "aes-128-gcm", "aes-256-gcm"}:
            raise Error("Supported ciphers: chacha20-ietf-poly1305, aes-128-gcm, aes-256-gcm.")
        if not password:
            raise Error("The access key has an empty password.")
        hostname, port = url.hostname, url.port
        try:
            address = ipaddress.ip_address(hostname)
            if address.version != 4:
                raise Error("This version supports IPv4 upstream endpoints only.")
            endpoint = str(address)
        except ValueError:
            lookup = resolver or socket.getaddrinfo
            endpoint = lookup(hostname, port, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        encoded = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        return {"host": hostname, "ip": endpoint, "port": port, "cipher": method,
                "uri": f"ss://{encoded}@{endpoint}:{port}"}
    except Error:
        raise
    except (ValueError, IndexError, OSError):
        raise Error("Invalid key or upstream hostname could not be resolved to IPv4.") from None


def read_target(args):
    if args.key_file:
        text = Path(args.key_file).read_text()
    else:
        text = getpass.getpass("VM B's ss:// access key (hidden): ")
    return parse_key(text)


def public_target(target):
    return {k: v for k, v in target.items() if k != "uri"}


def write_proxy(cfg, target):
    # JSON string quoting is valid YAML and prevents key content becoming YAML code.
    atomic(PROXY, "device: tun://" + TUN + "\ninterface: " + json.dumps(cfg["interface"]) +
           "\nmtu: 1400\nloglevel: warn\nproxy: " + json.dumps(target["uri"]) + "\n")


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect("/var/run/docker.sock")


def api(method, path, data=None, *, allowed=(200, 201, 204), timeout=45):
    conn = UnixHTTP("localhost", timeout=timeout)
    body = None if data is None else json.dumps(data)
    try:
        conn.request(method, path, body=body, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        payload = response.read()
        if response.status not in allowed:
            # Docker payloads may contain container environment secrets; don't print them.
            raise DockerError(f"Docker API {method} {path.split('?')[0]} returned HTTP {response.status}.", response.status)
        return json.loads(payload) if payload else None
    except (OSError, http.client.HTTPException):
        raise Error("Cannot communicate with the local Docker daemon.") from None
    finally:
        conn.close()


def cpath(name, suffix=""):
    return "/containers/" + urllib.parse.quote(name, safe="") + suffix


def inspect(name):
    return api("GET", cpath(name, "/json"))


def docker_exec(cfg, args, **kwargs):
    return run(DOCKER + ["exec"] + (["-i"] if "input" in kwargs else []) +
               [cfg["container"]] + list(args), **kwargs)


def stop_container(name):
    api("POST", cpath(name, "/stop?t=15"), allowed=(204, 304), timeout=25)


def start_container(name):
    api("POST", cpath(name, "/start"), allowed=(204, 304))


def managed_payload(original):
    result = copy.deepcopy(original["Config"])
    # Reuse exactly the existing local image, not a possibly moved image tag.
    result["Image"] = original["Image"]
    result["Labels"] = dict(result.get("Labels") or {})
    result["Labels"][LABEL] = "1"
    result["Labels"]["com.centurylinklabs.watchtower.enable"] = "false"
    host = copy.deepcopy(original["HostConfig"])
    host["CgroupParent"] = SLICE
    host["RestartPolicy"] = {"Name": "no", "MaximumRetryCount": 0}
    host["Dns"] = ["1.1.1.1"]
    host["DnsSearch"] = []
    host["DnsOptions"] = []
    result["HostConfig"] = host
    return result


def replace_container(cfg, original, payload):
    """Keep the stopped old container until the new one starts; roll back on failure."""
    name = cfg["container"]
    old_id = original["Id"]
    backup_name = "oc-backup-" + old_id[:12]
    cfg["transition"] = {"old_id": old_id, "backup_name": backup_name,
                         "restart": original["HostConfig"]["RestartPolicy"], "new_id": None}
    save(cfg)
    renamed = False
    new_id = None
    try:
        api("POST", cpath(old_id, "/update"), {"RestartPolicy": {"Name": "no"}})
        stop_container(old_id)
        api("POST", cpath(old_id, "/rename?name=" + backup_name))
        renamed = True
        created = api("POST", "/containers/create?name=" + urllib.parse.quote(name), payload)
        new_id = created["Id"]
        cfg["transition"]["new_id"] = new_id
        save(cfg)
        start_container(new_id)
        for _ in range(20):
            status = inspect(new_id)["State"]
            if not status["Running"]:
                raise Error("The replacement Outline container exited during startup.")
            if run(DOCKER + ["exec", new_id, "node", "--version"], check=False).returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise Error("The replacement Outline container did not become ready.")
    except BaseException:
        if new_id:
            api("DELETE", cpath(new_id, "?force=true"))
        if renamed:
            api("POST", cpath(old_id, "/rename?name=" + urllib.parse.quote(name)))
        api("POST", cpath(old_id, "/update"),
            {"RestartPolicy": original["HostConfig"]["RestartPolicy"]})
        start_container(old_id)
        cfg.pop("transition", None)
        save(cfg)
        raise
    # Do not remove volumes. Outline state remains on the original bind mounts.
    api("DELETE", cpath(old_id))
    cfg.pop("transition", None)
    save(cfg)


def expected_managed(item):
    return (item["HostConfig"].get("CgroupParent") == SLICE and
            item["HostConfig"]["RestartPolicy"]["Name"] == "no" and
            (item["Config"].get("Labels") or {}).get(LABEL) == "1" and
            (item["Config"].get("Labels") or {}).get("com.centurylinklabs.watchtower.enable") == "false")


def require_managed(cfg):
    item = inspect(cfg["container"])
    if not expected_managed(item):
        raise Error("Outline's managed Docker settings changed. Refusing to assume its traffic is protected.")
    return item


def table_rules(cfg):
    common = ["-m", "cgroup", "--path", SLICE, "-m", "conntrack", "--ctdir", "ORIGINAL",
              "-m", "addrtype", "!", "--dst-type", "LOCAL"]
    return [
        ("iptables", "mangle", "OC_ROUTE", common + ["-j", "MARK", "--set-mark", MARK]),
        # This must be POSTROUTING, not filter/OUTPUT: OUTPUT may see the old oif.
        # Match the group again, so another rule clearing the mark cannot bypass the guard.
        ("iptables", "mangle", "OC_POST", common + ["!", "-o", TUN, "-j", "DROP"]),
        ("ip6tables", "filter", "OC_V6", common + ["-j", "REJECT"]),
    ]


HOOKS = [("iptables", "mangle", "OUTPUT", "OC_ROUTE"),
         ("iptables", "mangle", "POSTROUTING", "OC_POST"),
         ("ip6tables", "filter", "OUTPUT", "OC_V6")]


def ensure_rule(tool, table, chain, rule, *, insert=False):
    base = [tool, "-w", "5", "-t", table]
    if run(base + ["-C", chain] + rule, check=False).returncode:
        run(base + (["-I", chain, "1"] if insert else ["-A", chain]) + rule)


def rule_selector(cfg, kind):
    if kind == "mark":
        return ["priority", str(MARK_RULE), "fwmark", MARK + "/0xffffffff", "lookup", str(TABLE)]
    return ["priority", str(PROBE_RULE), "from", cfg["probe"] + "/32", "lookup", str(TABLE)]


def ensure_ip_rule(cfg, kind):
    priority = MARK_RULE if kind == "mark" else PROBE_RULE
    rules = json.loads(run(["ip", "-j", "-4", "rule", "show"]).stdout)
    # Priorities are reserved by preflight; never delete/re-add a live routing rule.
    if not any(r.get("priority") == priority for r in rules):
        run(["ip", "-4", "rule", "add"] + rule_selector(cfg, kind))


def remove_ip_rule(cfg, kind):
    for _ in range(10):
        result = run(["ip", "-4", "rule", "del"] + rule_selector(cfg, kind), check=False)
        if result.returncode:
            break


def tun_up(cfg):
    if run(["ip", "link", "show", TUN], check=False).returncode:
        run(["ip", "tuntap", "add", "dev", TUN, "mode", "tun"])
    run(["ip", "address", "replace", cfg["probe"] + "/32", "dev", TUN])
    run(["ip", "link", "set", "dev", TUN, "mtu", "1400", "up"])
    run(["sysctl", "-w", f"net.ipv4.conf.{TUN}.rp_filter=2"])
    run(["ip", "route", "replace", "unreachable", "default", "metric", "32760", "table", str(TABLE)])
    run(["ip", "route", "replace", "default", "dev", TUN, "metric", "10", "table", str(TABLE)])
    ensure_ip_rule(cfg, "probe")


def ensure_tunnel(cfg):
    run(["systemctl", "start", TUN_SERVICE], timeout=90)
    tun_up(cfg)
    run(["systemctl", "is-active", "--quiet", TUN_SERVICE])


def attach(cfg):
    if not Path("/sys/fs/cgroup", SLICE).is_dir():
        raise Error("The stable Outline cgroup is missing.")
    ensure_ip_rule(cfg, "mark")
    route = run(["ip", "-4", "route", "get", "1.1.1.1", "mark", MARK]).stdout
    if "dev " + TUN not in route:
        raise Error("Marked packets do not select the tunnel. No client routing activated.")
    for tool, table, chain, rule in table_rules(cfg):
        if run([tool, "-w", "5", "-t", table, "-S", chain], check=False).returncode:
            run([tool, "-w", "5", "-t", table, "-N", chain])
        ensure_rule(tool, table, chain, rule)
    # Install guards first; then redirect new outbound packets.
    for tool, table, hook, chain in [HOOKS[1], HOOKS[2], HOOKS[0]]:
        ensure_rule(tool, table, hook, ["-j", chain], insert=True)


def detach(cfg):
    for tool, table, hook, chain in HOOKS:
        base = [tool, "-w", "5", "-t", table]
        for _ in range(10):
            if run(base + ["-C", hook, "-j", chain], check=False).returncode:
                break
            run(base + ["-D", hook, "-j", chain])
        run(base + ["-F", chain], check=False)
        run(base + ["-X", chain], check=False)
    remove_ip_rule(cfg, "mark")


def stop_tunnel(cfg):
    run(["systemctl", "stop", TUN_SERVICE], check=False, timeout=40)
    remove_ip_rule(cfg, "probe")
    run(["ip", "link", "delete", TUN], check=False)
    # This table is reserved exclusively by setup; no global route/firewall flushes.
    run(["ip", "-4", "route", "flush", "table", str(TABLE)], check=False)


def set_dns(cfg, enabled):
    text = "nameserver 1.1.1.1\n" if enabled else RESOLV.read_text()
    docker_exec(cfg, ["sh", "-c", "cat > /etc/resolv.conf"], input=text)


def trace_ip(body):
    match = re.search(r"^ip=(\S+)\s*$", body, re.M)
    if not match:
        raise Error("The HTTPS trace did not return an IP address.")
    try:
        return str(ipaddress.IPv4Address(match.group(1)))
    except ValueError:
        raise Error("The trace did not return an IPv4 address.") from None


def probe(cfg, *, container=False):
    if container:
        js = '''const https=require("https");
const req=https.get({hostname:"one.one.one.one",path:"/cdn-cgi/trace",family:4,
lookup:(h,o,cb)=>cb(null,"1.1.1.1",4)},r=>{r.pipe(process.stdout);
r.on("end",()=>{clearTimeout(timer);if(r.statusCode!==200)process.exitCode=1;});});
const timer=setTimeout(()=>{req.destroy(new Error("request timeout"));},20000);
req.on("error",e=>{clearTimeout(timer);console.error(e.message);process.exitCode=1;});'''
        body = docker_exec(cfg, ["node", "-e", js], timeout=30).stdout
    else:
        body = run(["curl", "--noproxy", "*", "-4", "--silent", "--show-error", "--fail",
                    "--interface", cfg["probe"], "--connect-timeout", "8", "--max-time", "20",
                    "--resolve", "one.one.one.one:443:1.1.1.1",
                    "https://one.one.one.one/cdn-cgi/trace"], timeout=25).stdout
    actual = trace_ip(body)
    expected = cfg.get("expected_exit")
    if expected and actual != expected:
        raise Error(f"Exit IP is {actual}, expected {expected}.")
    return actual


def test_upstream(cfg):
    address = probe(cfg)
    answer = run(["dig", "-4", "-b", cfg["probe"], "@1.1.1.1", "example.com", "A",
                  "+notcp", "+ignore", "+time=4", "+tries=1"], timeout=10).stdout
    if "status: NOERROR" not in answer or "(UDP)" not in answer or not re.search(r"ANSWER: [1-9]", answer):
        raise Error("UDP DNS through B failed; check B's UDP port and access key.")
    print(f"PASS: upstream HTTPS exit {address}; UDP DNS answered.", flush=True)
    return address


def test_container(cfg, upstream):
    require_managed(cfg)
    actual = probe(cfg, container=True)
    if actual != upstream:
        raise Error(f"Outline exits via {actual}, but the tested upstream exits via {upstream}.")
    # A real UDP DNS exchange originating inside the selected cgroup.
    js = '''const dgram=require("dgram"),s=dgram.createSocket("udp4");
const q=Buffer.from("4f4301000001000000000000076578616d706c6503636f6d0000010001","hex");
const timer=setTimeout(()=>{console.error("UDP DNS timeout");s.close();process.exitCode=1;},5000);
s.on("error",e=>{clearTimeout(timer);console.error(e.message);s.close();process.exitCode=1;});
s.on("message",(m,r)=>{if(r.address!=="1.1.1.1"||r.port!==53||m.length<12||m.readUInt16BE(0)!==0x4f43)return;
clearTimeout(timer);s.close();if(!(m[2]&128)||(m[3]&15)!==0||m.readUInt16BE(6)===0){process.exitCode=1;}
else console.log("UDP_DNS_OK");});s.send(q,53,"1.1.1.1");'''
    answer = docker_exec(cfg, ["node", "-e", js], timeout=10).stdout
    if "UDP_DNS_OK" not in answer:
        raise Error("Outline container UDP DNS failed.")
    print(f"PASS: Outline container HTTPS exit {actual}; container UDP DNS answered.", flush=True)
    return actual


def test_command(cfg):
    temporary = not cfg["enabled"]
    try:
        ensure_tunnel(cfg)
        upstream = test_upstream(cfg)
        if cfg["enabled"]:
            test_container(cfg, upstream)
        else:
            print("Chaining is OFF. Only the independent upstream was tested.")
        print("Also verify a real client connected to A; this test does not perform its inbound SS handshake.")
    finally:
        if temporary:
            stop_tunnel(cfg)


def unit_texts():
    return {
        SLICE: "[Unit]\nDescription=Stable Outline chaining cgroup\n[Slice]\n",
        TUN_SERVICE: f'''[Unit]
Description=Outline Shadowsocks upstream tunnel
Wants=network-online.target
After=network-online.target
[Service]
Type=exec
ExecStartPre={BIN} _tun-up
ExecStart={LIB}/tun2socks --config {PROXY}
Restart=on-failure
RestartSec=3
UMask=0077
LimitNOFILE=65536
''',
        SERVICE: f'''[Unit]
Description=Outline chain controller
Requires=docker.service {SLICE}
Wants=network-online.target
After=docker.service network-online.target {SLICE}
PartOf=docker.service
[Service]
Type=notify
NotifyAccess=main
ExecStart={BIN} _serve
Restart=on-failure
RestartSec=5
TimeoutStartSec=120
TimeoutStopSec=60
UMask=0077
[Install]
WantedBy=multi-user.target docker.service
''',
    }


def notify_ready():
    address = os.environ.get("NOTIFY_SOCKET")
    if address:
        if address.startswith("@"):
            address = "\0" + address[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(b"READY=1")


def serve():
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.set())
    # If a target update was interrupted by a reboot, resume with the last committed key.
    rollback_target_journal()
    cfg = load()
    if cfg.get("transition"):
        raise Error("Interrupted container replacement: run outline-chain recover.")
    try:
        item = require_managed(cfg)
        if cfg["enabled"]:
            ensure_tunnel(cfg)
            attach(cfg)
        else:
            detach(cfg)
            stop_tunnel(cfg)
        start_container(cfg["container"])
        set_dns(cfg, cfg["enabled"])
        last_id = item["Id"]
        notify_ready()
        while not stopped.wait(3):
            cfg = load()
            item = require_managed(cfg)
            if not item["State"]["Running"] or item["Id"] != last_id:
                if cfg["enabled"]:
                    ensure_tunnel(cfg)
                    attach(cfg)
                start_container(cfg["container"])
                set_dns(cfg, cfg["enabled"])
                last_id = item["Id"]
    finally:
        # Stop Outline BEFORE removing protection, including when Docker restarts.
        stop_container(cfg["container"])
        detach(cfg)
        stop_tunnel(cfg)


def interface_for(target):
    rows = json.loads(run(["ip", "-j", "-4", "route", "get", target["ip"]]).stdout)
    return rows[0]["dev"]


def validate_name(value, kind):
    pattern = r"[A-Za-z0-9_.:-]{1,15}" if kind == "interface" else r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}"
    if not re.fullmatch(pattern, value):
        raise Error(f"Invalid {kind} name.")
    return value


def preflight(args, target):
    if platform.system() != "Linux" or not Path("/run/systemd/system").is_dir():
        raise Error("A Linux host running systemd is required.")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if release.get("ID", "").strip('"') != "ubuntu":
        raise Error("This version targets Ubuntu 22.04 or newer.")
    if int(release["VERSION_ID"].strip('"').split(".")[0]) < 22:
        raise Error("Ubuntu 22.04 or newer is required.")
    if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        raise Error("Unified cgroup v2 is required.")
    if not Path("/dev/net/tun").exists():
        raise Error("/dev/net/tun is unavailable.")
    if BIN.exists() or LIB.exists() or (ROOT.exists() and any(ROOT.iterdir())):
        raise Error("Installation files already exist without active state; inspect/recover the earlier installation first.")
    if not shutil.which("docker"):
        raise Error("Install Outline/Docker first; this script does not install Outline.")
    packages = {"curl": "curl", "dig": "dnsutils", "ip": "iproute2", "iptables": "iptables", "ip6tables": "iptables"}
    missing = sorted({package for binary, package in packages.items() if not shutil.which(binary)})
    if missing:
        if not args.install_deps:
            raise Error("Missing packages: " + ", ".join(missing) + ". Re-run setup with --install-deps.")
        run(["apt-get", "update"], timeout=300)
        run(["apt-get", "install", "-y"] + missing, timeout=300)
    info = api("GET", "/info")
    if info.get("CgroupDriver") != "systemd" or str(info.get("CgroupVersion")) != "2":
        raise Error("Docker must use the systemd cgroup driver with cgroup v2.")
    if "nf_tables" not in run(["iptables", "--version"]).stdout:
        raise Error("This version requires the iptables-nft backend used in the tested setup.")
    original = inspect(args.container)
    if original["HostConfig"]["NetworkMode"] != "host" or not original["State"]["Running"]:
        raise Error("Outline must be a running Docker container using host networking.")
    if "outline/shadowbox" not in original["Config"]["Image"]:
        raise Error("This installer supports the standard outline/shadowbox Docker image.")
    if original["HostConfig"].get("CgroupParent"):
        raise Error("The container already has a custom cgroup parent; refusing to replace it.")
    if not original["Mounts"] or any(m["Type"] != "bind" for m in original["Mounts"]):
        raise Error("Only standard Outline installations with bind-mounted persistent state are supported.")
    if original["HostConfig"].get("AutoRemove"):
        raise Error("AutoRemove containers are unsupported.")
    rules = json.loads(run(["ip", "-j", "-4", "rule", "show"]).stdout)
    if any(r.get("priority") in (MARK_RULE, PROBE_RULE) or str(r.get("table")) == str(TABLE) for r in rules):
        raise Error("Routing table/priorities 20876–20877 are already in use.")
    if any(int(str(r.get("fwmark", "0")), 0) == int(MARK, 16) for r in rules):
        raise Error("The reserved firewall mark is already in use.")
    if run(["ip", "-4", "route", "show", "table", str(TABLE)], check=False).stdout.strip():
        raise Error("Routing table 20877 is already in use.")
    for device in (TUN, "outlineb"):
        if run(["ip", "link", "show", device], check=False).returncode == 0:
            raise Error(f"Interface {device} already exists. Remove the earlier manual setup first; see README.")
    existing = run(["iptables-save"]).stdout + run(["ip6tables-save"]).stdout
    if any(name in existing for name in (*CHAINS, "OB_B_ROUTE", "OB_B_POST", "OB_B_GUARD")):
        raise Error("Outline chain rules already exist. Clean up the previous/manual setup first.")
    if Path("/sys/fs/cgroup", SLICE).exists() or any((UNITS / name).exists() for name in unit_texts()):
        raise Error("Outline-chain units/cgroup already exist without state. Inspect the previous installation.")
    probe_address = str(ipaddress.IPv4Address(args.probe_address))
    if not ipaddress.IPv4Address(probe_address) in ipaddress.IPv4Network("198.18.0.0/15"):
        raise Error("The probe address must be within reserved benchmark range 198.18.0.0/15.")
    local = json.loads(run(["ip", "-j", "-4", "address", "show"]).stdout)
    addresses = {a["local"] for row in local for a in row.get("addr_info", [])}
    if target["ip"] in addresses:
        raise Error("B's endpoint is a local address on A; this would risk a proxy loop.")
    routes = json.loads(run(["ip", "-j", "-4", "route", "show", "table", "all"]).stdout)
    for route in routes:
        dest = route.get("dst", "default")
        if dest != "default" and ipaddress.IPv4Address(probe_address) in ipaddress.ip_network(dest, strict=False):
            raise Error("The probe address overlaps an existing route; choose --probe-address.")
    interface = validate_name(args.interface or interface_for(target), "interface")
    if interface in ("lo", TUN):
        raise Error("The upstream must use a physical/existing external interface.")
    run(["ip", "link", "show", interface])
    return original, interface, probe_address


def install_binary():
    try:
        arch, digest = RELEASES[platform.machine()]
    except KeyError:
        raise Error("Only x86_64 and aarch64 are supported.") from None
    url = f"https://github.com/xjasonlyu/tun2socks/releases/download/v{TUN_VERSION}/tun2socks-linux-{arch}.zip"
    print(f"Downloading verified tun2socks {TUN_VERSION} ({arch})…", flush=True)
    with urllib.request.urlopen(url, timeout=45) as response:
        data = response.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
        raise Error("tun2socks download failed SHA-256 verification.")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        name = f"tun2socks-linux-{arch}"
        if archive.getinfo(name).file_size > 64 * 1024 * 1024:
            raise Error("Unexpected binary size.")
        binary = archive.read(name)
    LIB.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=LIB)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(binary)
            os.fchmod(stream.fileno(), 0o755)
        os.replace(temp, LIB / "tun2socks")
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def setup(args):
    if STATE.exists():
        raise Error("Already installed. Use status, on, off, set-target, or uninstall; setup will not overwrite backups.")
    validate_name(args.container, "container")
    target = read_target(args)
    original, interface, probe_address = preflight(args, target)
    cfg = {"version": VERSION, "container": args.container, "interface": interface,
           "probe": probe_address, "enabled": False, "target": public_target(target),
           "expected_exit": args.expected_exit_ip, "ready": False}
    print("Setup will briefly recreate only Outline, preserve its bind-mounted state, and disable its Watchtower updates.", flush=True)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    ROOT.chmod(0o700)
    atomic(BACKUP, json.dumps(original, indent=2) + "\n")
    atomic(RESOLV, docker_exec(cfg, ["cat", "/etc/resolv.conf"]).stdout)
    save(cfg)
    try:
        install_binary()
        atomic(BIN, Path(__file__).read_text(), 0o755)
        write_proxy(cfg, target)
        for name, text in unit_texts().items():
            atomic(UNITS / name, text, 0o644)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "start", SLICE])
        ensure_tunnel(cfg)
        test_upstream(cfg)  # Fail before touching the original Outline container.
        stop_tunnel(cfg)
        replace_container(cfg, original, managed_payload(original))
        cfg["ready"] = True
        save(cfg)
        run(["systemctl", "enable", SERVICE])
        run(["systemctl", "start", SERVICE], timeout=125)
    except BaseException:
        print("Setup did not finish. Private backups were preserved. Run 'python3 outline_chain.py uninstall' to restore/clean up; if instructed, run recover first.", file=sys.stderr)
        raise
    print("Setup complete. Chaining is OFF; Outline still exits directly through A. Run 'sudo outline-chain on'.")


def toggle(cfg, enabled):
    if cfg.get("transition") or not cfg.get("ready"):
        raise Error("Installation is incomplete; recover/uninstall first.")
    run(["systemctl", "is-active", "--quiet", SERVICE])
    require_managed(cfg)
    if not enabled:
        cfg["enabled"] = False
        save(cfg)  # Reboots should now restore direct mode, even if cleanup is interrupted.
        detach(cfg)
        set_dns(cfg, False)
        stop_tunnel(cfg)
        print("OFF: Outline exits directly through A. This mode persists across reboots.")
        return
    was_enabled = cfg["enabled"]
    try:
        ensure_tunnel(cfg)
        upstream = test_upstream(cfg)
        set_dns(cfg, True)
        attach(cfg)
        actual = test_container(cfg, upstream)
        cfg["enabled"] = True
        save(cfg)
    except BaseException:
        if not was_enabled:
            detach(cfg)
            set_dns(cfg, False)
            stop_tunnel(cfg)
            print("Activation failed; restored direct mode through A.", file=sys.stderr)
        # If already on, leave guards in place; do not fail open after a failed check.
        raise
    print(f"ON: Outline container exits via {actual}. Reconnect existing clients. This mode persists across reboots.")


def set_target(cfg, args):
    target = read_target(args)
    original_cfg = copy.deepcopy(cfg)
    old_proxy = PROXY.read_text()
    local = json.loads(run(["ip", "-j", "-4", "address", "show"]).stdout)
    if target["ip"] in {a["local"] for row in local for a in row.get("addr_info", [])}:
        raise Error("The target is a local address on A; refusing a proxy loop.")
    cfg["target"] = public_target(target)
    cfg["expected_exit"] = args.expected_exit_ip
    atomic(TARGET_JOURNAL, json.dumps({"config": original_cfg, "proxy": old_proxy}) + "\n")
    try:
        write_proxy(cfg, target)
        candidate_proxy = PROXY.read_text()
        # Config contains no key; save only after probes succeed, so a failed update is reversible.
        run(["systemctl", "restart", TUN_SERVICE], timeout=90)
        ensure_tunnel(cfg)
        upstream = test_upstream(cfg)
        if cfg["enabled"]:
            test_container(cfg, upstream)
        if not TARGET_JOURNAL.exists() or PROXY.read_text() != candidate_proxy:
            raise Error("The controller restarted during the update; the update must be retried.")
        save(cfg)
        TARGET_JOURNAL.unlink()
    except BaseException:
        atomic(PROXY, old_proxy)
        save(original_cfg)
        TARGET_JOURNAL.unlink(missing_ok=True)
        run(["systemctl", "restart", TUN_SERVICE], check=False, timeout=90)
        print("Target update failed; restored the previous target configuration. Existing ON-mode guards remain in place.", file=sys.stderr)
        raise
    finally:
        if not original_cfg["enabled"]:
            stop_tunnel(original_cfg)
    print(f"Target updated to {target['ip']}:{target['port']}; mode remains {'ON' if cfg['enabled'] else 'OFF'}.")


def status(cfg):
    target = cfg["target"]
    print(f"Desired mode: {'ON' if cfg['enabled'] else 'OFF'}; setup {'complete' if cfg.get('ready') else 'incomplete'}")
    print(f"Outline: {cfg['container']}; upstream: {target['host']} ({target['ip']}):{target['port']}")
    print(f"Interface: {cfg['interface']}; tunnel: {TUN}; probe: {cfg['probe']}")
    for unit in (SERVICE, TUN_SERVICE):
        print(f"{unit}: " + run(["systemctl", "is-active", unit], check=False).stdout.strip())
    try:
        item = inspect(cfg["container"])
        print(f"Container running: {item['State']['Running']}; managed settings intact: {expected_managed(item)}")
    except Error as exc:
        print(str(exc))
    for tool, table, chain, _ in table_rules(cfg):
        result = run([tool, "-t", table, "-vnL", chain], check=False)
        if result.returncode == 0:
            print(result.stdout.rstrip())
    if cfg.get("transition"):
        print("Interrupted container replacement detected. Run recover.")
    if TARGET_JOURNAL.exists():
        print("Interrupted target update detected. Run recover to restore the last committed key.")


def recover(cfg):
    if rollback_target_journal():
        cfg = load()
        if cfg["enabled"]:
            run(["systemctl", "restart", TUN_SERVICE], timeout=90)
        else:
            stop_tunnel(cfg)
        print("Restored the last committed target. Run test to verify it.")
        return
    transition = cfg.get("transition")
    if not transition:
        raise Error("No interrupted container replacement is recorded.")
    # Do not stop the controller here: setup/replacement doesn't run it during transitions.
    old_id = transition["old_id"]
    try:
        old = inspect(old_id)
    except DockerError as exc:
        if exc.status != 404 or not transition.get("new_id"):
            raise
        item = inspect(transition["new_id"])
        if item["Name"].lstrip("/") != cfg["container"]:
            raise Error("Recovery name mismatch; no containers were changed.")
        # The replacement committed, but the process died before clearing its journal.
        cfg.pop("transition", None)
        save(cfg)
        print("Completed the replacement journal. Run uninstall to restore the original installation.")
        return
    new_id = transition.get("new_id")
    if not new_id and old["Name"].lstrip("/") == transition["backup_name"]:
        try:
            candidate = inspect(cfg["container"])
            if (candidate["Config"].get("Labels") or {}).get(LABEL) != "1":
                raise Error("An unrecognized container occupies the original name. No containers were deleted.")
            new_id = candidate["Id"]
        except DockerError as exc:
            if exc.status != 404:
                raise
    if new_id:
        api("DELETE", cpath(new_id, "?force=true"), allowed=(204, 404))
    if old["Name"].lstrip("/") != cfg["container"]:
        api("POST", cpath(old_id, "/rename?name=" + urllib.parse.quote(cfg["container"])))
    api("POST", cpath(old_id, "/update"), {"RestartPolicy": transition["restart"]})
    start_container(old_id)
    cfg.pop("transition", None)
    save(cfg)
    print("Original container recovered. Run uninstall to finish cleanup, then setup again if desired.")


def uninstall(cfg):
    if cfg.get("transition"):
        raise Error("Run recover before uninstalling an interrupted replacement.")
    run(["systemctl", "disable", "--now", SERVICE], check=False, timeout=90)
    current = inspect(cfg["container"])
    detach(cfg)
    stop_tunnel(cfg)
    if (current["Config"].get("Labels") or {}).get(LABEL) == "1":
        original = json.loads(BACKUP.read_text())
        payload = copy.deepcopy(original["Config"])
        # Restore the original tag too, so Watchtower can resume normal image updates.
        payload["HostConfig"] = copy.deepcopy(original["HostConfig"])
        replace_container(cfg, current, payload)
        docker_exec(cfg, ["sh", "-c", "cat > /etc/resolv.conf"], input=RESOLV.read_text())
    else:
        print("Container is not managed by this script; its Docker configuration was left intact.")
    for name in unit_texts():
        (UNITS / name).unlink(missing_ok=True)
    run(["systemctl", "stop", SLICE], check=False)
    run(["systemctl", "daemon-reload"])
    # Preserve original private backups for audit/recovery, outside the active install path.
    archive = ROOT.with_name("outline-chain-backup-" + time.strftime("%Y%m%d-%H%M%S"))
    os.rename(ROOT, archive)
    shutil.rmtree(LIB, ignore_errors=True)
    BIN.unlink(missing_ok=True)
    print(f"Uninstalled. Original Outline Docker settings restored where managed. Private backups: {archive}")


def parser():
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    result.add_argument("--version", action="version", version=VERSION)
    sub = result.add_subparsers(dest="command", required=True)
    install = sub.add_parser("setup", help="install and validate; leave chaining OFF")
    install.add_argument("--container", default="shadowbox")
    install.add_argument("--interface", help="A's external interface (auto-detected by default)")
    install.add_argument("--probe-address", default="198.18.254.1")
    install.add_argument("--install-deps", action="store_true", help="install missing curl/dig/iproute2/iptables packages")
    for cmd in (install, sub.add_parser("set-target", help="test and update B's access key, with rollback on failure")):
        cmd.add_argument("--key-file", help="read ss:// key from a local file instead of hidden prompt")
        cmd.add_argument("--expected-exit-ip", type=lambda s: str(ipaddress.IPv4Address(s)),
                         help="require this IPv4 exit address during tests")
    for name, help_text in [("on", "test, enable chaining, and persist ON mode"),
                            ("off", "restore direct routing and persist OFF mode"),
                            ("test", "test HTTPS/UDP upstream and, when ON, container egress"),
                            ("status", "show mode, service state, and packet counters"),
                            ("uninstall", "restore original Docker settings and remove this tool"),
                            ("recover", "recover an interrupted container replacement")]:
        sub.add_parser(name, help=help_text)
    # Internal entry points are accepted but intentionally absent from public help.
    for name in ("_serve", "_tun-up"):
        sub.add_parser(name)
    sub.metavar = "{setup,on,off,test,status,set-target,uninstall,recover}"
    return result


def dispatch(args):
    if args.command == "setup":
        return setup(args)
    cfg = load()
    if args.command == "_serve":
        return serve()
    if args.command == "_tun-up":
        return tun_up(cfg)
    if TARGET_JOURNAL.exists() and args.command not in ("recover", "status"):
        raise Error("A target update was interrupted. Run recover first.")
    if args.command == "on":
        return toggle(cfg, True)
    if args.command == "off":
        return toggle(cfg, False)
    if args.command == "test":
        return test_command(cfg)
    if args.command == "set-target":
        return set_target(cfg, args)
    if args.command == "status":
        return status(cfg)
    if args.command == "uninstall":
        return uninstall(cfg)
    if args.command == "recover":
        return recover(cfg)


def main(argv=None):
    args = parser().parse_args(argv)
    if platform.system() != "Linux" or os.geteuid() != 0:
        print("Run this command as root on VM A (Ubuntu Linux).", file=sys.stderr)
        return 1
    try:
        if args.command.startswith("_"):
            # Called synchronously by systemd while a public command may hold the lock.
            dispatch(args)
        else:
            with open("/run/outline-chain.lock", "a") as lock:
                os.chmod(lock.name, 0o600)
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Error("Another outline-chain command is running.") from None
                dispatch(args)
        return 0
    except KeyboardInterrupt:
        print("Interrupted. Run status; recover/uninstall if setup was interrupted.", file=sys.stderr)
        return 130
    except (Error, OSError, ValueError, zipfile.BadZipFile) as exc:
        print("ERROR: " + scrub(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
