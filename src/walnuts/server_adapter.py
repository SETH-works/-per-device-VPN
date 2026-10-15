"""Owned, fail-closed Linux objects for the single PC-STREAM pilot.

This module is inert on import. Only the explicit server-* CLI commands call
the operating system, and installation never advertises an exit node.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
try:
    import fcntl
except ImportError:  # Windows development host
    fcntl = None
    import msvcrt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
from typing import Callable, Sequence
import uuid

from .pilot import PilotSpec, _validate_spec


class AdapterError(RuntimeError):
    pass


Runner = Callable[[Sequence[str], str | None], str]


def _system_runner(argv: Sequence[str], stdin: str | None = None) -> str:
    try:
        result = subprocess.run(
            list(argv), input=stdin, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterError(f"could not run {shlex.join(argv)}: {exc}") from exc
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise AdapterError(f"{shlex.join(argv)} failed: {detail}")
    return result.stdout


@dataclass(frozen=True, slots=True)
class Preflight:
    blockers: tuple[str, ...]
    observed: dict[str, str]


class LinuxPilotAdapter:
    """Reconcile only state named and journaled as Walnuts-owned."""

    OWNER = "project-walnuts/pc-stream-vpnbook/v1"

    def __init__(
        self,
        spec: PilotSpec,
        *,
        state_path: str | Path = "/var/lib/walnuts/pc-stream-pilot.json",
        runner: Runner = _system_runner,
        is_root: bool | None = None,
        deployment_evidence: dict[str, bool] | None = None,
    ):
        self.spec = spec
        self.state_path = Path(state_path)
        self.lock_path = self.state_path.with_suffix(".lock")
        self.runner = runner
        self.is_root = (os.geteuid() == 0) if is_root is None and hasattr(os, "geteuid") else (is_root is True)
        self.deployment_evidence = deployment_evidence or {}
        self._static_blockers = tuple(_validate_spec(spec))

    def _run(self, *argv: str, stdin: str | None = None) -> str:
        return self.runner(argv, stdin)

    def _state(self) -> dict | None:
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise AdapterError(f"pilot ownership state is unreadable: {exc}") from exc
        if raw.get("owner") != self.OWNER or raw.get("version") != 1:
            raise AdapterError("pilot state has an unknown owner or version; refusing to touch network objects")
        return raw

    def _write_state(self, state: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".walnuts-", dir=self.state_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(state, stream, sort_keys=True, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.state_path)
            if os.name == "posix" and hasattr(os, "O_DIRECTORY"):
                dir_fd = os.open(self.state_path.parent, os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def _locked(self):
        class Lock:
            def __init__(inner, path: Path):
                inner.path = path
                inner.stream = None

            def __enter__(inner):
                inner.path.parent.mkdir(parents=True, exist_ok=True)
                inner.stream = inner.path.open("a+")
                if fcntl:
                    fcntl.flock(inner.stream.fileno(), fcntl.LOCK_EX)
                else:
                    inner.stream.seek(0)
                    inner.stream.write("0")
                    inner.stream.flush()
                    inner.stream.seek(0)
                    msvcrt.locking(inner.stream.fileno(), msvcrt.LK_LOCK, 1)
                return inner

            def __exit__(inner, *_args):
                if fcntl:
                    fcntl.flock(inner.stream.fileno(), fcntl.LOCK_UN)
                else:
                    inner.stream.seek(0)
                    msvcrt.locking(inner.stream.fileno(), msvcrt.LK_UNLCK, 1)
                inner.stream.close()
        return Lock(self.lock_path)

    def preflight(self) -> Preflight:
        """Read-only checks; every probe is an argv call and never uses a shell."""
        blockers = list(self._static_blockers)
        observed: dict[str, str] = {}
        try:
            state = self._state()
        except AdapterError as exc:
            state = None
            blockers.append(str(exc))
        owned = set((state or {}).get("installed", [])) | set((state or {}).get("owned", []))
        instance = (state or {}).get("instance", "")

        def read(key: str, *argv: str) -> str:
            try:
                value = self._run(*argv).strip()
            except AdapterError as exc:
                value = f"ERROR: {exc}"
            observed[key] = value
            return value

        ns = read("namespaces", "ip", "netns", "list")
        if not any(line.split()[0] == self.spec.namespace for line in ns.splitlines() if line.split()):
            blockers.append("vpnbook namespace is absent")
        wg_addr = read("wg_address", "ip", "-n", self.spec.namespace, "-4", "addr", "show", "dev", self.spec.tunnel_interface)
        if self.spec.expected_namespace_ipv4 not in wg_addr:
            blockers.append("vpnbook wg-vpn address differs from the approved observation")
        ns_default = read("namespace_default", "ip", "-n", self.spec.namespace, "-4", "route", "show", "default")
        if not ns_default or any("dev wg-vpn" not in line for line in ns_default.splitlines()):
            blockers.append("vpnbook IPv4 default is not exclusively through wg-vpn")
        for resolver in (self.spec.dns_resolver_ipv4,):
            route = read(f"dns_route_{resolver}", "ip", "-n", self.spec.namespace, "-4", "route", "get", resolver)
            if "dev wg-vpn" not in route:
                blockers.append(f"namespace DNS resolver {resolver} does not route through wg-vpn")
        ns_v6_default = read("namespace_ipv6_default", "ip", "-n", self.spec.namespace, "-6", "route", "show", "default")
        if ns_v6_default.startswith("ERROR:"):
            blockers.append("could not verify that vpnbook has no IPv6 default route")
        elif ns_v6_default:
            blockers.append("vpnbook has an IPv6 default route")
        handshake = read("wireguard_handshakes", "ip", "netns", "exec", self.spec.namespace, "wg", "show", self.spec.tunnel_interface, "latest-handshakes")
        now = int(datetime.now(timezone.utc).timestamp())
        ages = [now - int(row.split()[-1]) for row in handshake.splitlines()
                if row.split() and row.split()[-1].isdigit() and int(row.split()[-1]) > 0]
        if not ages or min(ages) > 180:
            blockers.append("WireGuard handshake is missing or older than 180 seconds")

        tailscale_json = read("tailscale_status", "tailscale", "status", "--json")
        pc_stream_online = False
        try:
            peer_map = json.loads(tailscale_json).get("Peer", {})
            pc_stream_online = any(
                self.spec.client_tailscale_ipv4 in peer.get("TailscaleIPs", [])
                and self.spec.client_tailscale_ipv6 in peer.get("TailscaleIPs", [])
                and "STREAM" in peer.get("DNSName", "").upper()
                and peer.get("Online") is True
                for peer in peer_map.values()
            )
        except (json.JSONDecodeError, AttributeError):
            pass
        observed["pc_stream_identity"] = "online/verified" if pc_stream_online else "not found or offline"
        if not pc_stream_online:
            blockers.append("PC-STREAM identity or online state does not match the approved Tailscale addresses")

        iptables_version = read("iptables_version", "iptables", "-V")
        if "nf_tables" not in iptables_version:
            blockers.append("host iptables backend is no longer iptables-nft")
        forward = read("iptables_forward", "iptables-save", "-t", "filter")
        nat = read("iptables_nat", "iptables-save", "-t", "nat")
        required_filter = (
            "-A FORWARD -j ts-forward",
            "-A ts-forward -i tailscale0 -j MARK --set-xmark 0x40000/0xff0000",
            "-A ts-forward -m mark --mark 0x40000/0xff0000 -j ACCEPT",
        )
        required_nat = (
            "-A POSTROUTING -j ts-postrouting",
            "-A ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE",
        )
        if any(rule not in forward for rule in required_filter):
            blockers.append("Tailscale forward marking/ACCEPT rules differ from the reviewed rules")
        if any(rule not in nat for rule in required_nat):
            blockers.append("Tailscale marked postrouting MASQUERADE rule differs from the reviewed rules")
        ns_filter = read("namespace_filter", "ip", "netns", "exec", self.spec.namespace, "iptables-save", "-t", "filter")
        ns_nat = read("namespace_nat", "ip", "netns", "exec", self.spec.namespace, "iptables-save", "-t", "nat")
        if "-P FORWARD ACCEPT" not in ns_filter:
            blockers.append("vpnbook namespace forwarding policy differs from the reviewed ACCEPT baseline")
        if any(line.startswith("-A ") for line in ns_nat.splitlines()):
            blockers.append("vpnbook namespace has existing NAT rules that need specific review")
        if "-P FORWARD DROP" not in forward:
            blockers.append("host FORWARD default policy differs from the reviewed DROP policy")
        observed["forward_policy"] = "DROP" if "-P FORWARD DROP" in forward else "unknown"

        prefs = read("tailscale_prefs", "tailscale", "debug", "prefs")
        try:
            pref_data = json.loads(prefs)
            if pref_data.get("NetfilterMode") != 2 or pref_data.get("NoSNAT") is not False:
                blockers.append("Tailscale must remain netfilter mode on with SNAT enabled")
            if pref_data.get("ExitNodeID") or pref_data.get("ExitNodeIP"):
                blockers.append("SethLinux is already selecting an exit node; review its preferences")
        except json.JSONDecodeError:
            blockers.append("Tailscale preferences could not be parsed")

        default = read("main_default", "ip", "-4", "route", "show", "default")
        if self.spec.expected_host_default not in default:
            blockers.append("SethLinux main IPv4 default route differs from the approved baseline")
        ip_forward = read("ipv4_forward", "sysctl", "-n", "net.ipv4.ip_forward")
        ipv6_forward = read("ipv6_forward", "sysctl", "-n", "net.ipv6.conf.all.forwarding")
        if ip_forward != "1" or ipv6_forward != "0":
            blockers.append("host forwarding sysctls differ from the approved IPv4-only baseline")

        rules4 = read("rules4", "ip", "-4", "rule", "show")
        rules6 = read("rules6", "ip", "-6", "rule", "show")
        for pref, expected_name, family, address, terminal in (
            (self.spec.rule_priority, "source_lookup", rules4, self.spec.client_tailscale_ipv4, str(self.spec.route_table)),
            (self.spec.rule_priority + 1, "ipv4_fallback", rules4, self.spec.client_tailscale_ipv4, "unreachable"),
        ):
            lines = [line for line in family.splitlines() if line.lstrip().startswith(f"{pref}:")]
            if lines and not (expected_name in owned and any(address in line and terminal in line for line in lines)):
                blockers.append(f"IPv4 policy priority {pref} is occupied by a non-Walnuts rule")
        lines6 = [line for line in rules6.splitlines() if line.lstrip().startswith(f"{self.spec.rule_priority}:")]
        if lines6 and not ("ipv6_block" in owned and any(self.spec.client_tailscale_ipv6 in line and "unreachable" in line for line in lines6)):
            blockers.append(f"IPv6 policy priority {self.spec.rule_priority} is occupied by a non-Walnuts rule")
        table = read("route_table_198", "ip", "-4", "route", "show", "table", str(self.spec.route_table))
        expected_route = f"default via {ipaddress.ip_interface(self.spec.namespace_veth_ipv4).ip} dev {self.spec.host_veth}"
        if table and not ("host_route" in owned and all(line.strip() == expected_route for line in table.splitlines())):
            blockers.append("dedicated route table is already populated by an unexpected route")
        host_routes = read("host_routes", "ip", "-4", "route", "show", "table", "all")
        subnet = str(ipaddress.ip_interface(self.spec.host_veth_ipv4).network)
        if subnet in host_routes and "veth" not in owned:
            blockers.append("proposed veth subnet overlaps an existing host route")
        host_links = read("host_veth", "ip", "-j", "link", "show", "dev", self.spec.host_veth)
        ns_links = read("namespace_veth", "ip", "-n", self.spec.namespace, "-j", "link", "show", "dev", self.spec.namespace_veth)
        for key, value, name in (("host_veth", host_links, self.spec.host_veth), ("namespace_veth", ns_links, self.spec.namespace_veth)):
            if not value.startswith("ERROR:"):
                try:
                    parsed = json.loads(value)
                    alias = parsed[0].get("ifalias", "")
                except (json.JSONDecodeError, IndexError, TypeError):
                    alias = ""
                if name not in {self.spec.host_veth, self.spec.namespace_veth} or alias != f"walnuts:{instance}" or "veth" not in owned:
                    blockers.append(f"interface {name} exists but is not the exact journaled Walnuts veth")
        nft_tables = read("nft_tables", "nft", "list", "tables")
        if f"table inet {self.spec.firewall_table}" in nft_tables:
            host_table = read("host_nft_existing", "nft", "list", "table", "inet", self.spec.firewall_table)
            if "host_nft" not in owned or f"{self.OWNER}; instance={instance}" not in host_table:
                blockers.append("host nftables table name is already in use by an unknown owner")
        ns_tables = read("namespace_nft_tables", "ip", "netns", "exec", self.spec.namespace, "nft", "list", "tables")
        if f"table inet {self.spec.namespace_firewall_table}" in ns_tables:
            ns_table = read("namespace_nft_existing", "ip", "netns", "exec", self.spec.namespace, "nft", "list", "table", "inet", self.spec.namespace_firewall_table)
            if "ns_nft" not in owned or f"{self.OWNER}; instance={instance}" not in ns_table:
                blockers.append("namespace nftables table name is already in use by an unknown owner")
        required_evidence = ("client_identity_confirmed", "forwarding_baseline_recorded", "namespace_default_via_tunnel_confirmed",
            "namespace_kill_switch_confirmed", "tailscale_source_pre_snat_confirmed", "tailscale_snat_to_veth_confirmed",
            "dns_resolver_reachable_only_via_tunnel", "ipv6_drop_path_verified", "existing_forwarding_dependencies_reviewed",
            "boot_guard_persistence_verified", "ssh_and_protected_services_baselined")
        blockers.extend(f"deployment evidence {key} is not approved" for key in required_evidence if not self.deployment_evidence.get(key, False))
        return Preflight(tuple(dict.fromkeys(blockers)), observed)

    def _spec_hash(self) -> str:
        values = {name: getattr(self.spec, name) for name in self.spec.__dataclass_fields__}
        return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()

    def _nft_host(self, instance: str) -> str:
        return f'''table inet {self.spec.firewall_table} {{
  comment "{self.OWNER}; instance={instance}"
  chain forward_guard {{
    type filter hook forward priority 10; policy accept;
    iifname "tailscale0" ip saddr {self.spec.client_tailscale_ipv4} oifname != "{self.spec.host_veth}" counter drop
    iifname "tailscale0" ip6 saddr {self.spec.client_tailscale_ipv6} counter drop
  }}
}}
'''

    def _nft_namespace(self, instance: str) -> str:
        host_ip = str(ipaddress.ip_interface(self.spec.host_veth_ipv4).ip)
        return f'''table inet {self.spec.namespace_firewall_table} {{
  comment "{self.OWNER}; instance={instance}"
  chain forward_guard {{
    type filter hook forward priority 10; policy accept;
    iifname "{self.spec.namespace_veth}" ip saddr {host_ip} oifname "{self.spec.tunnel_interface}" accept
    iifname "{self.spec.tunnel_interface}" oifname "{self.spec.namespace_veth}" ct state established,related accept
    iifname "{self.spec.namespace_veth}" counter drop
    oifname "{self.spec.namespace_veth}" counter drop
  }}
  chain input_guard {{
    type filter hook input priority 10; policy accept;
    iifname "{self.spec.namespace_veth}" counter drop
  }}
  chain pilot_postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    iifname "{self.spec.namespace_veth}" ip saddr {host_ip} oifname "{self.spec.tunnel_interface}" masquerade
  }}
}}
'''

    def commands(self, instance: str = "WALNUTS_INSTANCE") -> tuple[tuple[str, ...], ...]:
        """Exact ordered command argv preview; nft programs are returned separately."""
        host_ip = str(ipaddress.ip_interface(self.spec.host_veth_ipv4).ip)
        ns_ip = str(ipaddress.ip_interface(self.spec.namespace_veth_ipv4).ip)
        return (
            ("nft", "-f", "-"),
            ("ip", "-4", "rule", "add", "pref", str(self.spec.rule_priority + 1), "iif", "tailscale0", "from", f"{self.spec.client_tailscale_ipv4}/32", "unreachable"),
            ("ip", "-6", "rule", "add", "pref", str(self.spec.rule_priority), "iif", "tailscale0", "from", f"{self.spec.client_tailscale_ipv6}/128", "unreachable"),
            ("ip", "link", "add", self.spec.host_veth, "type", "veth", "peer", "name", self.spec.namespace_veth),
            ("ip", "link", "set", self.spec.host_veth, "alias", f"walnuts:{instance}"),
            ("ip", "link", "set", self.spec.namespace_veth, "netns", self.spec.namespace),
            ("ip", "-n", self.spec.namespace, "link", "set", self.spec.namespace_veth, "alias", f"walnuts:{instance}"),
            ("ip", "addr", "add", self.spec.host_veth_ipv4, "dev", self.spec.host_veth),
            ("ip", "-n", self.spec.namespace, "addr", "add", self.spec.namespace_veth_ipv4, "dev", self.spec.namespace_veth),
            ("ip", "link", "set", self.spec.host_veth, "up"),
            ("ip", "-n", self.spec.namespace, "link", "set", self.spec.namespace_veth, "up"),
            ("ip", "netns", "exec", self.spec.namespace, "nft", "-f", "-"),
            ("ip", "route", "add", "default", "via", ns_ip, "dev", self.spec.host_veth, "table", str(self.spec.route_table)),
            ("ip", "-4", "rule", "add", "pref", str(self.spec.rule_priority), "iif", "tailscale0", "from", f"{self.spec.client_tailscale_ipv4}/32", "lookup", str(self.spec.route_table)),
        )

    def ensure_guard(self) -> dict:
        if not self.is_root:
            raise AdapterError("server guard installation requires root")
        with self._locked():
            state = self._state()
            if state and state.get("phase") == "REMOVED":
                state = None
            state = state or {
                "version": 1, "owner": self.OWNER, "instance": uuid.uuid4().hex,
                "spec_sha256": self._spec_hash(), "phase": "INITIALIZING", "owned": [], "installed": [],
            }
            if state["spec_sha256"] != self._spec_hash():
                raise AdapterError("pilot configuration changed since state capture; refusing to reconcile")
            state["phase"] = "GUARDING"
            self._write_state(state)
            objects = [
                ("host_nft", ("nft", "-f", "-"), self._nft_host(state["instance"])),
                ("ipv4_fallback", ("ip", "-4", "rule", "add", "pref", str(self.spec.rule_priority + 1), "iif", "tailscale0", "from", f"{self.spec.client_tailscale_ipv4}/32", "unreachable"), None),
                ("ipv6_block", ("ip", "-6", "rule", "add", "pref", str(self.spec.rule_priority), "iif", "tailscale0", "from", f"{self.spec.client_tailscale_ipv6}/128", "unreachable"), None),
            ]
            try:
                try:
                    self._run("ip", "link", "show", "dev", "tailscale0")
                    ts_link = True
                except AdapterError:
                    ts_link = False
                for name, argv, stdin in objects:
                    if name in {"ipv4_fallback", "ipv6_block"} and not ts_link:
                        continue
                    present = False
                    if name == "host_nft":
                        try:
                            current = self._run("nft", "list", "table", "inet", self.spec.firewall_table)
                        except AdapterError:
                            current = ""
                        marker = f"{self.OWNER}; instance={state['instance']}"
                        if current and marker not in current:
                            raise AdapterError("Walnuts nft table name exists with a different ownership marker")
                        present = bool(current)
                    elif name in {"ipv4_fallback", "ipv6_block"}:
                        family = "-4" if name == "ipv4_fallback" else "-6"
                        rules = self._run("ip", family, "rule", "show")
                        pref = str(self.spec.rule_priority + 1 if name == "ipv4_fallback" else self.spec.rule_priority) + ":"
                        matching = [line for line in rules.splitlines() if line.lstrip().startswith(pref)]
                        if matching:
                            expected = (self.spec.client_tailscale_ipv4 if name == "ipv4_fallback" else self.spec.client_tailscale_ipv6)
                            if not any(expected in line and "unreachable" in line and "tailscale0" in line for line in matching):
                                raise AdapterError(f"policy priority {pref[:-1]} is occupied by a different rule")
                            present = True
                    if present:
                        if name not in state.setdefault("installed", []):
                            state["installed"].append(name)
                            state.setdefault("owned", []).append(name)
                            self._write_state(state)
                        continue
                    if name not in state["owned"]:
                        state["owned"].append(name)
                    state["phase"] = f"INSTALLING_{name.upper()}"
                    self._write_state(state)
                    self._run(*argv, stdin=stdin)
                    state.setdefault("installed", []).append(name)
                    self._write_state(state)
                state["phase"] = "GUARDED"
                self._write_state(state)
                return state
            except Exception:
                state["phase"] = "BLOCKED_PARTIAL"
                self._write_state(state)
                raise

    def _object_present(self, name: str, state: dict) -> bool:
        """Return true only for an object that matches this journal's identity."""
        alias = f"walnuts:{state['instance']}"
        if name == "host_nft":
            try:
                current = self._run("nft", "list", "table", "inet", self.spec.firewall_table)
            except AdapterError:
                return False
            if f"{self.OWNER}; instance={state['instance']}" not in current:
                raise AdapterError("host nftables ownership marker differs")
            return True
        if name in {"veth", "host_alias", "host_up", "host_addr"}:
            argv = ("ip", "-j", "link", "show", "dev", self.spec.host_veth)
            try: data = json.loads(self._run(*argv))[0]
            except AdapterError: return False
            except (json.JSONDecodeError, IndexError, TypeError): raise AdapterError("host veth state is unreadable")
            if data.get("ifalias") != alias:
                if name == "host_alias" and not data.get("ifalias") and "veth" in state.get("installed", []): return False
                raise AdapterError("host veth exists without the exact Walnuts ownership alias")
            if name in {"veth", "host_alias"}: return True
            if name == "host_up": return "UP" in data.get("flags", [])
            addresses = self._run("ip", "-j", "-4", "addr", "show", "dev", self.spec.host_veth)
            try: found = {f"{a['local']}/{a['prefixlen']}" for x in json.loads(addresses) for a in x.get("addr_info", [])}
            except (json.JSONDecodeError, KeyError, TypeError): return False
            return self.spec.host_veth_ipv4 in found
        if name in {"peer_move", "peer_alias", "ns_up", "ns_addr"}:
            try: data = json.loads(self._run("ip", "-n", self.spec.namespace, "-j", "link", "show", "dev", self.spec.namespace_veth))[0]
            except AdapterError: return False
            except (json.JSONDecodeError, IndexError, TypeError): raise AdapterError("namespace veth state is unreadable")
            if name == "peer_move" and not data.get("ifalias") and "host_alias" in state.get("installed", []):
                try: host = json.loads(self._run("ip", "-j", "link", "show", "dev", self.spec.host_veth))[0]
                except (AdapterError, json.JSONDecodeError, IndexError, TypeError): raise AdapterError("cannot verify veth pair ownership")
                if host.get("ifalias") == alias and host.get("link_index") == data.get("ifindex"): return True
            if data.get("ifalias") != alias:
                if name == "peer_alias" and not data.get("ifalias") and "peer_move" in state.get("installed", []): return False
                raise AdapterError("namespace veth exists without the exact Walnuts ownership alias")
            if name in {"peer_move", "peer_alias"}: return True
            if name == "ns_up": return "UP" in data.get("flags", [])
            addresses = self._run("ip", "-n", self.spec.namespace, "-j", "-4", "addr", "show", "dev", self.spec.namespace_veth)
            try: found = {f"{a['local']}/{a['prefixlen']}" for x in json.loads(addresses) for a in x.get("addr_info", [])}
            except (json.JSONDecodeError, KeyError, TypeError): return False
            return self.spec.namespace_veth_ipv4 in found
        if name == "ns_nft":
            try: current = self._run("ip", "netns", "exec", self.spec.namespace, "nft", "list", "table", "inet", self.spec.namespace_firewall_table)
            except AdapterError: return False
            if f"{self.OWNER}; instance={state['instance']}" not in current: raise AdapterError("namespace nftables ownership marker differs")
            return True
        if name == "host_route":
            routes = self._run("ip", "-4", "route", "show", "table", str(self.spec.route_table)).splitlines()
            expected = f"default via {ipaddress.ip_interface(self.spec.namespace_veth_ipv4).ip} dev {self.spec.host_veth}"
            if routes and any(line.strip() != expected for line in routes): raise AdapterError("pilot route table contains an unexpected route")
            return bool(routes)
        if name == "source_lookup":
            rules = self._run("ip", "-4", "rule", "show").splitlines()
            matches = [line for line in rules if line.lstrip().startswith(f"{self.spec.rule_priority}:")]
            if matches and not any(self.spec.client_tailscale_ipv4 in line and str(self.spec.route_table) in line and "tailscale0" in line for line in matches):
                raise AdapterError("pilot source rule priority is occupied by another rule")
            return bool(matches)
        return False

    def install(self, *, dry_run: bool = False) -> tuple[Preflight, tuple[str, ...]]:
        preflight = self.preflight()
        if preflight.blockers:
            return preflight, ()
        if dry_run:
            return preflight, tuple(shlex.join(item) for item in self.commands())
        if not self.is_root:
            raise AdapterError("server installation requires root")
        with self._locked():
            state = self._state()
            if state and state["spec_sha256"] != self._spec_hash():
                raise AdapterError("installed pilot does not match this config")
        state = self.ensure_guard()
        # Guards are installed first and remain if any later operation fails.
        host_ip = str(ipaddress.ip_interface(self.spec.host_veth_ipv4).ip)
        ns_ip = str(ipaddress.ip_interface(self.spec.namespace_veth_ipv4).ip)
        objects = [
            ("veth", ("ip", "link", "add", self.spec.host_veth, "type", "veth", "peer", "name", self.spec.namespace_veth), None),
            ("host_alias", ("ip", "link", "set", self.spec.host_veth, "alias", f"walnuts:{state['instance']}"), None),
            ("peer_move", ("ip", "link", "set", self.spec.namespace_veth, "netns", self.spec.namespace), None),
            ("peer_alias", ("ip", "-n", self.spec.namespace, "link", "set", self.spec.namespace_veth, "alias", f"walnuts:{state['instance']}"), None),
            ("host_addr", ("ip", "addr", "add", self.spec.host_veth_ipv4, "dev", self.spec.host_veth), None),
            ("ns_addr", ("ip", "-n", self.spec.namespace, "addr", "add", self.spec.namespace_veth_ipv4, "dev", self.spec.namespace_veth), None),
            ("host_up", ("ip", "link", "set", self.spec.host_veth, "up"), None),
            ("ns_up", ("ip", "-n", self.spec.namespace, "link", "set", self.spec.namespace_veth, "up"), None),
            ("ns_nft", ("ip", "netns", "exec", self.spec.namespace, "nft", "-f", "-"), self._nft_namespace(state["instance"])),
            ("host_route", ("ip", "route", "add", "default", "via", ns_ip, "dev", self.spec.host_veth, "table", str(self.spec.route_table)), None),
            ("source_lookup", ("ip", "-4", "rule", "add", "pref", str(self.spec.rule_priority), "iif", "tailscale0", "from", f"{self.spec.client_tailscale_ipv4}/32", "lookup", str(self.spec.route_table)), None),
        ]
        try:
            for name, argv, stdin in objects:
                if name in state.get("installed", []) and self._object_present(name, state):
                    continue
                if self._object_present(name, state):
                    state.setdefault("installed", []).append(name)
                    if name not in state["owned"]: state["owned"].append(name)
                    self._write_state(state)
                    continue
                if name not in state["owned"]: state["owned"].append(name)
                state["phase"] = f"INSTALLING_{name.upper()}"
                self._write_state(state)
                self._run(*argv, stdin=stdin)
                state.setdefault("installed", []).append(name)
                self._write_state(state)
            state["phase"] = "INSTALLED"
            state["installed_at"] = datetime.now(timezone.utc).isoformat()
            state["note"] = "Exit-node advertisement is intentionally not managed by this adapter."
            self._write_state(state)
            return preflight, tuple(shlex.join(item) for item in self.commands())
        except Exception:
            state["phase"] = "BLOCKED_PARTIAL"
            self._write_state(state)
            raise

    def recover(self) -> dict:
        """Reassert drop guards; never removes protection or advertises routes."""
        return self.ensure_guard()

    def health(self) -> dict:
        """Read-only operational probes; failures report BLOCKED and never relax guards."""
        preflight = self.preflight()
        probes: dict[str, str] = {}
        def probe(name: str, *argv: str) -> str:
            try:
                probes[name] = self._run(*argv).strip()
            except AdapterError as exc:
                probes[name] = f"ERROR: {exc}"
            return probes[name]
        default = probe("host_default", "ip", "-4", "route", "show", "default")
        public_ip = probe("vpn_public_ipv4", "ip", "netns", "exec", self.spec.namespace,
                          "curl", "-4", "--fail", "--silent", "--show-error", "--max-time", "8", "https://api.ipify.org")
        dns_path = probe("dns_route", "ip", "-n", self.spec.namespace, "-4", "route", "get", self.spec.dns_resolver_ipv4)
        dns_query = probe("dns_query", "ip", "netns", "exec", self.spec.namespace,
                          "dig", "+time=3", "+tries=1", "+short", "@" + self.spec.dns_resolver_ipv4, "example.com", "A")
        ipv6 = probe("namespace_ipv6_probe", "ip", "netns", "exec", self.spec.namespace,
                     "curl", "-6", "--fail", "--silent", "--max-time", "5", "https://api64.ipify.org")
        services = {name: probe("service_" + name, "systemctl", "is-active", name)
                    for name in ("ssh.service", "tailscaled.service", "vpnbook.service", "docker.service", "nginx.service")}
        active_units = probe("active_units", "systemctl", "list-units", "--type=service", "--state=active", "--no-legend")
        containers = probe("docker_containers", "docker", "ps", "--format", "{{.Names}}")
        protected = {
            "ssh": services["ssh.service"] == "active",
            "tailscale": services["tailscaled.service"] == "active",
            "vpnbook": services["vpnbook.service"] == "active",
            "docker": services["docker.service"] == "active",
            "nginx": services["nginx.service"] == "active",
            "pihole": "pihole" in containers.lower(),
            "cloudflare": "cloudflared" in active_units.lower() or "cloudflare" in containers.lower(),
            "minecraft": "minecraft" in active_units.lower() or "bedrock" in active_units.lower() or "minecraft" in containers.lower() or "bedrock" in containers.lower(),
        }
        peer_json = probe("tailscale_status", "tailscale", "status", "--json")
        client_seen = False
        try:
            peers = json.loads(peer_json).get("Peer", {}).values()
            client_seen = any(self.spec.client_tailscale_ipv4 in peer.get("TailscaleIPs", [])
                              and "STREAM" in peer.get("DNSName", "").upper() for peer in peers)
        except (json.JSONDecodeError, AttributeError):
            pass
        nft = probe("host_guard", "nft", "list", "table", "inet", self.spec.firewall_table)
        state = self._state()
        guard_ok = False
        if state:
            try:
                guard_ok = all(self._object_present(k, state) for k in
                               ("host_nft", "ipv4_fallback", "ipv6_block"))
            except AdapterError:
                guard_ok = False
        healthy = (not preflight.blockers and public_ip == self.spec.expected_vpn_ipv4
                   and bool(dns_query) and not dns_query.startswith("ERROR:")
                   and "dev wg-vpn" in dns_path and ipv6.startswith("ERROR:")
                    and self.spec.expected_host_default in default
                   and all(protected.values())
                   and client_seen and guard_ok)
        return {"mode": "HEALTHY" if healthy else ("BLOCKED_FAIL_CLOSED" if guard_ok else "DEGRADED"),
                "healthy": healthy, "guard_present": guard_ok, "pc_stream_seen": client_seen,
                "protected_services": protected,
                "preflight_blockers": list(preflight.blockers), "probes": probes}

    def status(self) -> dict:
        state = self._state()
        preflight = self.preflight()
        guard_ok = False
        if state:
            try:
                guard_ok = all(self._object_present(k, state) for k in
                               ("host_nft", "ipv4_fallback", "ipv6_block"))
            except AdapterError:
                guard_ok = False
        return {
            "mode": "UNINITIALIZED" if state is None else (state["phase"] if guard_ok else "DEGRADED"),
            "recorded_phase": None if state is None else state["phase"],
            "guarded": guard_ok,
            "preflight_blockers": list(preflight.blockers),
            "observed": preflight.observed,
            "exit_node_advertised_by_adapter": False,
        }

    def remove(self, *, confirm_client_direct: bool = False) -> None:
        """Remove exact owned objects only after separate client-side DIRECT action."""
        if not confirm_client_direct:
            raise AdapterError("refusing teardown: explicitly switch PC-STREAM to DIRECT first and pass --confirm-client-direct")
        if not self.is_root:
            raise AdapterError("server teardown requires root")
        with self._locked():
            state = self._state()
            if not state:
                return
            owned = set(state.get("installed", []))
            state["phase"] = "REMOVING"
            self._write_state(state)
            try:
                if "source_lookup" in owned:
                    self._run("ip", "-4", "rule", "del", "pref", "5000", "iif", "tailscale0", "from", f"{self.spec.client_tailscale_ipv4}/32", "lookup", str(self.spec.route_table))
                if "host_route" in owned:
                    self._run("ip", "route", "del", "default", "via", str(ipaddress.ip_interface(self.spec.namespace_veth_ipv4).ip), "dev", self.spec.host_veth, "table", str(self.spec.route_table))
                if "ns_nft" in owned:
                    self._delete_owned_nft(self.spec.namespace, self.spec.namespace_firewall_table, state["instance"])
                if "veth" in owned:
                    alias = self._run("ip", "-j", "link", "show", "dev", self.spec.host_veth)
                    if f"walnuts:{state['instance']}" not in alias:
                        raise AdapterError("host veth ownership alias differs; refusing to delete it")
                    self._run("ip", "link", "del", "dev", self.spec.host_veth)
                if "host_nft" in owned:
                    self._delete_owned_nft(None, self.spec.firewall_table, state["instance"])
                if "ipv4_fallback" in owned:
                    self._run("ip", "-4", "rule", "del", "pref", str(self.spec.rule_priority + 1), "iif", "tailscale0", "from", f"{self.spec.client_tailscale_ipv4}/32", "unreachable")
                if "ipv6_block" in owned:
                    self._run("ip", "-6", "rule", "del", "pref", str(self.spec.rule_priority), "iif", "tailscale0", "from", f"{self.spec.client_tailscale_ipv6}/128", "unreachable")
                state["phase"] = "REMOVED"
                self._write_state(state)
            except Exception:
                state["phase"] = "BLOCKED_PARTIAL"
                self._write_state(state)
                raise

    def _delete_owned_nft(self, namespace: str | None, table: str, instance: str) -> None:
        prefix = ("ip", "netns", "exec", namespace) if namespace else ()
        rendered = self._run(*prefix, "nft", "list", "table", "inet", table)
        marker = f"{self.OWNER}; instance={instance}"
        if marker not in rendered:
            raise AdapterError(f"nftables table inet {table} ownership marker differs; refusing to delete it")
        self._run(*prefix, "nft", "delete", "table", "inet", table)

