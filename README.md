# Outline Chain

A standalone Python tool for this topology:

```text
Outline client → Outline on A → tun2socks on A → Outline on B → Internet
```

Run the tool **on A only**. B keeps its normal Outline installation; its access-key port must accept TCP and UDP from A.

## Quick start on a new VM pair

Copy `outline_chain.py` to A. Both VMs should already have working Outline installations.

```bash
sudo python3 outline_chain.py setup --install-deps
sudo outline-chain on
sudo outline-chain test
sudo outline-chain status
```

`setup` prompts for **B's full `ss://` access key**, with hidden input. Do not enter A's key. Setup installs the command as `/usr/local/sbin/outline-chain` and leaves chaining **OFF** until you run `on`.

Setup briefly recreates A's Outline container using the same local image, environment, command, and bind-mounted persistent state. Existing Outline access keys and management settings remain in the persisted state. Clients may need to reconnect. Private backups are kept before replacement.

For an explicit interface, a non-default container name, or an expected exit address:

```bash
sudo python3 outline_chain.py setup --install-deps --container shadowbox --interface eth0 --expected-exit-ip 203.0.113.10
```

Replace the example exit IP with B's actual public exit address. If omitted, tests display the upstream exit and verify that Outline's exit matches it, without assuming B's listening address is also its exit address.

## Commands

| Command | Effect |
| --- | --- |
| `sudo outline-chain on` | Test B, enable routing through B, test Outline's egress, and persist ON mode. |
| `sudo outline-chain off` | Restore direct routing through A and original container DNS; persist OFF mode. |
| `sudo outline-chain test` | Test upstream HTTPS and UDP DNS; when ON, also test both from inside the Outline container. |
| `sudo outline-chain status` | Show desired mode, actual service state, target endpoint, container configuration checks, and firewall counters. |
| `sudo outline-chain set-target` | Prompt for another B key, test it, and retain the existing ON/OFF mode. |
| `sudo outline-chain uninstall` | Restore original container settings, remove the controller and its network rules, and retain private backups. |
| `sudo outline-chain recover` | Recover a recorded interrupted container replacement or target update. |

**OFF means clients still work, but exit directly through A.** It does not disable the Outline server.

`test` in OFF mode temporarily starts a separate test tunnel, then removes it. It does not redirect Outline clients.

### Update B or rotate its key

```bash
sudo outline-chain set-target
sudo outline-chain test
```

Optionally require a particular exit IP:

```bash
sudo outline-chain set-target --expected-exit-ip 203.0.113.20
```

A failed test restores the previous target configuration. While ON, routing guards remain in place during replacement/restart, so a failed upstream does not deliberately fall back to A. Existing client connections may need to reconnect after changing targets.

The existing external interface stays selected during a target update. For a move to another network interface, uninstall and set up again with the new `--interface`.

### Noninteractive key input

Both `setup` and `set-target` accept `--key-file /path/to/key.txt`. The file contains only the full `ss://` key. Restrict its permissions to the owner, and do not pass the key itself as a command-line argument.

```bash
sudo python3 outline_chain.py setup --install-deps --key-file /secure/path/b-key.txt
sudo outline-chain set-target --key-file /secure/path/new-b-key.txt
```

## Supported environment

- Ubuntu 22.04 or newer, systemd, Python 3.10+, and the `iptables-nft` backend.
- x86_64 or aarch64; Docker using the systemd cgroup driver and cgroup v2.
- Standard `quay.io/outline/shadowbox` container with host networking and bind-mounted persistent state.
- One managed Outline container per host; default name `shadowbox`.
- Plain Shadowsocks `ss://` keys using `chacha20-ietf-poly1305`, `aes-128-gcm`, or `aes-256-gcm`.
- IPv4 upstream endpoints. Hostnames are resolved to an IPv4 address at setup/update time and pinned. Re-run `set-target` if that address changes.

Dynamic `ssconf://` keys, WebSocket transports, prefix/plugin extensions, IPv6 upstream endpoints, rootless Docker, Docker bridge networking, and custom container/storage layouts are not supported by this version.

While ON, non-local outbound IPv6 from Outline is blocked. IPv4 and TCP/UDP chaining are supported. Other host services keep their own routing and DNS.

## Persistence and container updates

The controller keeps Outline under the stable `outlinechain.slice` cgroup. Routing targets this parent instead of the disposable Docker container ID.

To prevent Outline starting directly before its ON-mode routing is installed, setup sets **only the managed Outline container's** Docker restart policy to `no`. A systemd controller then starts its network protection before starting the container and restarts it if it exits. The chosen ON/OFF mode survives a reboot. The controller is also tied to Docker service starts/restarts.

Setup sets `com.centurylinklabs.watchtower.enable=false` **on Outline only**. Other containers and Watchtower itself are not changed. Do not use an updater that ignores this exclusion or recreate the managed container with unrelated settings.

**Outline will not receive automatic image updates while managed.** To upgrade Outline using your existing installation/update procedure:

1. Run `sudo outline-chain uninstall` to restore its original Docker restart policy, image tag, labels, and DNS.
2. Upgrade Outline normally and confirm it works directly.
3. Run setup again and then `on`.

This is a deliberate lifecycle choice; retaining a stale per-container cgroup rule or relying on a polling timer would leave gaps during replacement/startup.

## What is installed or changed

| Location/resource | Purpose |
| --- | --- |
| `/usr/local/sbin/outline-chain` | Installed Python command. |
| `/usr/local/lib/outline-chain/tun2socks` | Pinned tun2socks v2.7.0 binary, checked against the published SHA-256 hash. |
| `/etc/outline-chain/` | Configuration, secret proxy key, DNS backup, and original Docker inspection snapshot. Directory mode 0700; private files 0600. |
| `outline-chain.service` | Starts/supervises the managed container and applies the selected mode. |
| `outline-chain-tunnel.service` | Runs and restarts tun2socks. A proxy failure leaves its network protection in place. |
| `outlinechain.slice` | Stable parent cgroup for Outline's sockets. |
| `ocss0` | Dedicated tunnel interface. |
| `198.18.254.1/32` | Default probe source address; change with setup's `--probe-address` if it overlaps an existing route. |
| Table `20877`, priorities `20876` and `20877`, mark `0x4f430001` | Reserved policy-routing resources, checked for conflicts during setup. |
| `OC_ROUTE`, `OC_POST`, `OC_V6` | Tool-owned firewall chains. Global rulesets are never flushed. |

The routing mark is applied in `mangle/OUTPUT` to non-local, original-direction connections from Outline's cgroup. Client-facing replies are excluded. The output-interface guard is in **`mangle/POSTROUTING`**, avoiding the premature interface check that broke the initial manual configuration. It checks the cgroup again instead of relying on the mark still being present.

While ON, Outline's container DNS is `1.1.1.1` and follows its tunnel routing. OFF restores the saved resolver file. Host DNS is not edited.

Uninstall preserves `/etc/outline-chain-backup-TIMESTAMP/` with root-only permissions. It contains the old key and configuration; remove that backup yourself when it is no longer needed.

## Moving the earlier manual setup to this tool

For a **new VM pair**, skip this section.

For the VM A configured in the accompanying conversation, first remove that temporary configuration. These names/table numbers refer specifically to that manual setup:

```bash
sudo outline-route-rollback
sudo systemctl stop outline-upstream-test
sudo ip -4 rule del priority 20266 from 198.18.0.1/32 lookup 20266
sudo ip -4 route flush table 20266
sudo ip link delete outlineb
```

This temporarily restores direct client egress through A. Then run this tool's setup and `on`. Leave the old `/etc/outline-upstream/` files until the new configuration passes its tests; the script does not import or overwrite them.

Setup refuses to overlap the known manual tunnel or its firewall chains. Do not run the old apply/rollback commands against the new tool's state.

## Troubleshooting and verification

```bash
sudo outline-chain status
sudo outline-chain test
sudo journalctl -u outline-chain.service -n 60 --no-pager
sudo journalctl -u outline-chain-tunnel.service -n 60 --no-pager | sed -E 's#ss://[^[:space:]]+#[REDACTED]#g'
```

If `on` fails while previously OFF, it restores direct mode. If a test fails while already ON, it leaves the guards in place instead of silently enabling direct access. Use `off` when you explicitly want direct egress restored.

After a failed/interrupted setup, follow its error message. `recover` handles a recorded interrupted replacement; `uninstall` restores the original container and removes installation remnants. You can invoke these with `sudo python3 outline_chain.py COMMAND` if the installed command was not yet created.

Do not manually delete Docker backup containers named `oc-backup-*` while a recovery is pending.

The automated network probes use Cloudflare's HTTPS trace and DNS resolver; a destination outage or restriction can also cause a test failure. Treat a failure as a reason to inspect, not proof that the key is invalid.

After enabling, connect a real Outline client using **A's key** and check [the trace page](https://one.one.one.one/cdn-cgi/trace). Its `ip=` should be B's exit address. The script tests container egress but does **not** perform a client's inbound Shadowsocks handshake to A.

Before relying on a new deployment, verify the client after a reboot and confirm traffic fails while `outline-chain-tunnel.service` is stopped, then start that service again. Run those checks during a suitable interruption window.

## Validation included with this package

The manual routing design was verified on the Ubuntu 22.04 pair in the conversation. The packaged installer has **25 automated regression tests**, covering key formats/redaction, the POSTROUTING guard, preservation of container configuration, rollback, interrupted key updates, file permissions, and boot/shutdown ordering.

The complete installer has **not** been executed on a fresh Ubuntu VM in this workspace. The tests use mocked Docker/systemd/network operations; they do not replace a real installation/reboot test.

```bash
python3 -m unittest discover -s tests -v
```

Implementation references: [tun2socks release files](https://github.com/xjasonlyu/tun2socks/releases/expanded_assets/v2.7.0), [Docker container options](https://docs.docker.com/reference/cli/docker/container/run/), and [Linux packet-matching extensions](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html).
