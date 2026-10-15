# Project Walnuts Phase 1 operator runbook

This is the one-PC-STREAM VPNBook pilot. Nothing in the repository installs or selects an exit node until an operator runs an explicit action. Do not treat these commands as approval to deploy.

## Current design

Path: `PC-STREAM → Tailscale → SethLinux tailscale0 → source-policy table 198 → wlnh0/wlnn0 → vpnbook → wg-vpn`.

The server adapter first installs `table inet walnuts_pilot` at forward priority 10. It drops PC-STREAM IPv4 when the selected egress is anything except `wlnh0`, and drops that PC-STREAM Tailscale IPv6 source. This later nftables base chain is deliberately separate from Tailscale's early ACCEPT in its iptables-nft chain. The host then installs an unreachable IPv4 fallback at priority 5001 and IPv6 fallback at 5000. Priority 5000 routes only source `100.70.142.17/32` arriving on `tailscale0` to table 198. Table 198 contains only `default via 169.254.240.2 dev wlnh0`.

The namespace table `inet walnuts_vpnbook_pilot` permits only the veth source through `wg-vpn`, permits established return packets, drops other packets arriving from `wlnn0`, drops unsolicited traffic targeting that veth, blocks client-originated access to namespace-local services on `wlnn0`, and masquerades the pilot source only out `wg-vpn`. Tailscale's reviewed mark `0x40000/0xff0000` is not reused. Tailscale's own MASQUERADE must be confirmed to translate the forwarded source to `169.254.240.1`; this adapter does not weaken that requirement or provide a host-route fallback. If that observation fails, stop.

`walnuts-pilot-guard.service` recreates the host drop table on boot before `tailscaled.service`. A narrow `tailscaled.service` drop-in requires that guard to succeed before Tailscale starts. If guard installation fails at boot, Tailscale will be unavailable (LAN SSH remains the recovery path) instead of exposing a persisted exit-node advertisement through the ISP route. The guard remains installed if the namespace/tunnel is unavailable. `walnuts-pilot.service` runs the adapter after Tailscale, VPNBook, and network-online. Do not advertise the exit node unless both services and the health checks are verified. The boot rehearsal and failure behavior still require live verification.

On PC-STREAM, VPNBOOK mode captures the current firewall profile actions and Tailscale DNS preference before changing anything. It adds only rules in the Walnuts group, enables Windows Firewall with outbound default Block on all profiles, allows the Tailscale interface, the Tailscale service transport, and DHCP renewal, and blocks all IPv6. It then disables Tailscale DNS acceptance, sets approved IPv4 resolvers, and selects SethLinux with LAN access disabled. Any failure after lockdown leaves outbound Block in place. There is no automatic DIRECT fallback. DIRECT requires an explicit warning and `-ConfirmDirect`; emergency recovery additionally requires the exact phrase shown below. The script never edits Hyper-V or other adapter DNS.

DNS queries and DoH from applications use the Tailscale interface while VPNBOOK is active; the physical interface has no general application allow. The Tailscale service itself is allowed to reach its control/transport endpoints over the underlay, and DHCP can renew. These are limited bootstrap/maintenance exceptions. This pilot blocks IPv6 globally on PC-STREAM while selected. It does not control other tailnet devices, physical access to SethLinux, router policies, applications using their own encrypted proxy/VPN, or host processes outside PC-STREAM. Client firewall behavior must be verified on the exact Windows build before use.

## Deployment blockers still open

- Refresh the two Tailscale device identities and addresses and verify PC-STREAM online.
- Obtain privileged read-only ruleset capture: host `iptables-save` filter/nat, `ip6tables-save`, `nft list ruleset`; the equivalent inside `vpnbook`; and validate the exact Tailscale forward/SNAT order. Gateway currently cannot run privileged reads because its trusted-path check rejects the installed sudo-rs path.
- Prove in a controlled packet capture/conntrack observation that Tailscale SNAT exits toward `wlnh0` as `169.254.240.1`, including return translation. Do not infer this solely from Tailscale's generic MASQUERADE rule.
- Refresh namespace address, routes, DNS paths, handshake, VPN/direct public egress, IPv6 failure, rule/table/interface/subnet availability, and current service baselines.
- Verify the namespace's persistent kill switch and the Windows Firewall rule/profile behavior. Inspect DNS queries on the exit side, not just successful resolution.
- Review the complete tailnet policy and device tag owner; the policy fragment below is additive and cannot revoke prior broad grants. Run Tailscale's policy test against the merged policy.
- Rehearse systemd boot/restart and interruption in an isolated Linux namespace/VM. Confirm the host nft guard survives Tailscale restarts and nftables reloads. No live reboot rehearsal has been performed.
- Refresh the example config's `[evidence]` values only after those checks. The server install command refuses to run while required evidence remains false.

## Exact staged commands (after review and separate approval)

The following paths assume this repository is staged at `/opt/walnuts` on SethLinux and the approved runtime config is installed at `/etc/walnuts/pilot.toml`. The units use the system Python directly, so no package or venv installation is needed. The config must contain fresh observed values and reviewed `[evidence]` entries. Do not set evidence true to bypass a missing observation. Stage the source after approval with `sudo git clone https://github.com/SETH-works/-per-device-VPN.git /opt/walnuts`, then install a private config file (do not use the blocked example verbatim): `sudo install -d -m 0700 /etc/walnuts` and `sudo install -m 0600 /path/to/reviewed-pilot.toml /etc/walnuts/pilot.toml`.

### SethLinux — read-only preflight and dry run

```sh
sudo env PYTHONPATH=/opt/walnuts/src /usr/bin/python3 -m walnuts.cli server-preflight /etc/walnuts/pilot.toml
sudo env PYTHONPATH=/opt/walnuts/src /usr/bin/python3 -m walnuts.cli server-dry-run /etc/walnuts/pilot.toml
```

Review the JSON output, including both complete nftables payloads. No changes are made. `server-preflight` must return no blockers and match the approved snapshot. If any value differs, stop and regenerate the change review.

### SethLinux — stage the persistent drop guard

```sh
sudo install -m 0644 /opt/walnuts/systemd/walnuts-pilot-guard.service /etc/systemd/system/walnuts-pilot-guard.service
sudo install -D -m 0644 /opt/walnuts/systemd/tailscaled.service.d/10-walnuts-pilot-guard.conf /etc/systemd/system/tailscaled.service.d/10-walnuts-pilot-guard.conf
sudo systemctl daemon-reload
sudo systemctl enable --now walnuts-pilot-guard.service
sudo env PYTHONPATH=/opt/walnuts/src /usr/bin/python3 -m walnuts.cli server-status /etc/walnuts/pilot.toml
```

Confirm the host table marker and client-specific IPv4/IPv6 drops. If Tailscale is not up yet, the native nft guard remains active and the policy-route fallback can be reconciled later. Do not start the pilot service or advertise an exit node until the remaining stages pass.

### PC-STREAM — arm client protection with no exit selected

From an elevated PowerShell window in the client folder:

```powershell
.\walnuts-client.ps1 -Mode Arm -PlanOnly -ConfigPath .\pilot-client.json
```

After reviewing the plan and verifying the current client identity/interface, arm the kill switch:

```powershell
.\walnuts-client.ps1 -Mode Arm -Confirm -ConfigPath .\pilot-client.json
.\walnuts-client.ps1 -Mode Status -ConfigPath .\pilot-client.json
```

`Arm` sets outbound default Block, IPv6 blocking, approved DNS and Tailscale DNS settings, but does not select an exit node. Confirm `KillSwitchActive: true`, an empty exit-node selection, and blocked public traffic. This intentionally leaves PC-STREAM without public internet until the route is ready.

### SethLinux — install the route adapter, still before advertising

```sh
sudo install -m 0644 /opt/walnuts/systemd/walnuts-pilot.service /etc/systemd/system/walnuts-pilot.service
sudo systemctl daemon-reload
sudo systemctl enable --now walnuts-pilot.service
sudo env PYTHONPATH=/opt/walnuts/src /usr/bin/python3 -m walnuts.cli server-status /etc/walnuts/pilot.toml
sudo env PYTHONPATH=/opt/walnuts/src /usr/bin/python3 -m walnuts.cli server-health /etc/walnuts/pilot.toml
```

Only after successful server status/health and the PC-STREAM kill switch check, perform the separately approved tailnet policy merge and Tailscale exit-node advertisement/approval. On SethLinux, the exact advertisement toggle is:

```sh
sudo tailscale set --advertise-exit-node
```

Approve SethLinux as an exit node in the Tailscale admin console, verify the device tag and policy tests, then explicitly select VPNBOOK on PC-STREAM:

```powershell
.\walnuts-client.ps1 -Mode VPNBOOK -Confirm -ConfigPath .\pilot-client.json
.\walnuts-client.ps1 -Mode Status -ConfigPath .\pilot-client.json
```

Repeat the egress, DNS, IPv6, and host-service checks. Keep the prior management session open throughout.

## Exact tailnet policy addition

Merge this fragment into the existing policy; do not replace the policy. It defines the pilot tag as admin-owned and grants only that tag `autogroup:internet`. The `tests` entries are intended to prove pilot allow and a representative non-pilot deny. Validate against the current policy format and run official policy tests before saving. The live tailnet policy and device tag ownership have not been inspected, so this is a proposed diff, not a verified merge.

```json
{
  "tagOwners": {
    "tag:pc-stream-vpnbook-pilot": ["autogroup:admin"]
  },
  "grants": [
    {
      "src": ["tag:pc-stream-vpnbook-pilot"],
      "dst": ["autogroup:internet"],
      "ip": ["*"]
    }
  ],
  "tests": [
    {"src": "100.70.142.17", "accept": ["autogroup:internet:*"]},
    {"src": "100.70.142.18", "deny": ["autogroup:internet:*"]}
  ]
}
```

Tailscale validates the merged policy and its tests when saved; the current policy must also be inspected for broad grants. The offline `audit_exit_node_access()` helper flags other grants/legacy ACL entries that can authorize internet or wildcard destinations. It is only a structural audit, not a substitute for official tailnet policy tests. See [Tailscale policy syntax and tests](https://tailscale.com/docs/reference/syntax/policy-file). The grant permits PC-STREAM to use any authorized exit node; it does not select SethLinux.

## Acceptance checks and recovery

On every trial, verify `server-health` (namespace, handshake age, VPN public IPv4, DNS route/query, IPv6 failure, host default route, SSH/Tailscale/VPNBook services, peer identity, host guard), plus PC-STREAM status and live DNS/effective public egress. Current values `147.135.15.16` and `198.29.53.14` are historical observations and must be refreshed.

A failed VPNBOOK check leaves PC-STREAM blocked. Do not invoke DIRECT automatically. The owner may restore DIRECT explicitly:

```powershell
.\walnuts-client.ps1 -Mode DIRECT -ConfirmDirect -Confirm -ConfigPath .\pilot-client.json
```

Emergency owner recovery is deliberately separate:

```powershell
.\walnuts-client.ps1 -Mode EmergencyDirect -ConfirmDirect -EmergencyPhrase 'I UNDERSTAND THIS DISABLES VPN PROTECTION' -Confirm -ConfigPath .\pilot-client.json
```

Then verify PC-STREAM's exit node is empty, Ethernet DNS is DHCP-managed, and original firewall profile actions are restored. Server rollback must never be used as a substitute for this client action.

After DIRECT is verified, server rollback is exact-object only:

```sh
sudo systemctl disable --now walnuts-pilot.service
sudo tailscale set --advertise-exit-node=false
sudo env PYTHONPATH=/opt/walnuts/src /usr/bin/python3 -m walnuts.cli server-remove /etc/walnuts/pilot.toml --confirm-client-direct
sudo systemctl disable --now walnuts-pilot-guard.service
sudo rm /etc/systemd/system/tailscaled.service.d/10-walnuts-pilot-guard.conf
sudo systemctl daemon-reload
```

`server-remove` deletes only journaled rules/tables/routes/veths with matching Walnuts ownership. If any marker or identity differs, it stops and leaves the guard in place. After confirming the owned tables are gone, remove `/etc/systemd/system/walnuts-pilot.service` and `/etc/systemd/system/walnuts-pilot-guard.service` and run `sudo systemctl daemon-reload`; never flush shared nftables, Docker, or Tailscale rules. Withdraw only the pilot's exit-node advertisement with `sudo tailscale set --advertise-exit-node=false`, then remove `/etc/systemd/system/tailscaled.service.d/10-walnuts-pilot-guard.conf` and run `sudo systemctl daemon-reload`. Revert only the reviewed tailnet policy addition as a separately approved action.
