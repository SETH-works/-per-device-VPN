# Project Walnuts Phase 1 deployment change set

**Superseded for Windows activation:** the controller now disables Arm/VPNBOOK/Verify because Defender rule precedence cannot establish the required underlay boundary. This document retains historical server design context. Follow the [current operator runbook](phase1-operator-runbook.md); do not execute the former client rollout from this document.

**State: prepared offline; not applied.** No Tailscale exit advertisement, tailnet policy change, firewall/routing change, DNS change, or PC-STREAM mode switch has occurred. The change set below is limited to PC-STREAM. It is not cleared for execution until the privileged read-only gates are complete and the user approves this exact plan.

## Current observations

| Fact | Observation | Evidence time / status |
|---|---|---|
| SethLinux Tailscale | `100.112.153.81`, Tailscale `1.104.1-t7f4efe814-g8da26756c`, running | Live `tailscale status --json`, 2026-10-14 21:10 EDT |
| PC-STREAM | Tailscale hostname `STREAM`, Windows, `100.70.142.17`, `fd7a:115c:a1e0::7f3b:8e11`, offline at observation | Live peer status, 2026-10-14 21:10 EDT; refresh before deployment |
| Existing exit node | SethLinux `ExitNodeOption=false`; peer records showed `ExitNodeOption=false` | Live status, 2026-10-14 21:10 EDT |
| Tailscale preferences | `AdvertiseRoutes=null`, `ExitNodeID=""`, `RouteAll=false`, `NoSNAT=false`, `NetfilterMode=2` (`on`), `CorpDNS=true` | Live `tailscale debug prefs`, 2026-10-14 21:11 EDT |
| Host route policy | Priorities 5210/5230/5250 use mark `0x80000/0xff0000`; 5270 looks up table 52; no current rules at 5000/5001 | Live `ip rule show`, 2026-10-14 21:11 EDT |
| Host route | IPv4 default via `192.168.1.1` on `eno1`; `192.168.1.41/24` | Live route table, 2026-10-14 21:11 EDT |
| Forwarding | IPv4 enabled (`1`); IPv6 disabled (`0`) | Live sysctl read, 2026-10-14 21:11 EDT |
| Firewall tooling | `iptables v1.8.11 (nf_tables)`; an unprivileged read of iptables/nft rules was denied | Live version/read, 2026-10-14 21:11 EDT |
| Namespace/VPNBook | `vpnbook`, `wg-vpn`, `10.104.12.196/32`, default through `wg-vpn`; DNS `1.1.1.1`, `8.8.8.8`; VPN egress `147.135.15.16`; no namespace IPv6 default/connectivity | User-supplied manual observation; refresh before deployment |
| Direct egress | `198.29.53.14` | User-supplied previous observation; refresh before deployment |
| VPNBook service | Existing service remains active | User-supplied previous observation; refresh before deployment |

Tailscale `NoSNAT=false` establishes that SNAT is enabled in preferences. It does **not** reveal the exact installed rule, match, or translated address. The Tailscale forwarding/filter/NAT rules and namespace firewall could not be read because Gateway's unprivileged SSH user received `Permission denied`; its known sudo trusted-executable issue remains unresolved. Do not infer the effective packet path from preferences alone.

## Packet path and proposed isolated objects

```text
PC-STREAM 100.70.142.17 (explicitly selects SethLinux exit node)
  -> encrypted Tailscale flow -> tailscale0 on SethLinux
  -> source+iif policy at priority 5000 -> table 198
  -> wlnh0 169.254.240.1/30 <-> wlnn0 169.254.240.2/30 in vpnbook
  -> vpnbook default via wg-vpn -> namespace-only masquerade -> VPNBook
```

The `/30` above is a proposed reservation, not yet confirmed free. The table id 198 currently has no FIB table; priorities 5000/5001 are currently before the observed Tailscale rules. Recheck all assignments at deployment time. The host's main default route stays via `eno1`.

The host uses `iptables-nft`. Because the active FORWARD policy is reported as DROP and Tailscale manages rules in its own chains, the proposed host integration is one exact jump from the existing IPv4 FORWARD traversal to a pilot-owned `WALNUTS_PILOT` chain. Its insertion point must be chosen from the privileged snapshot: after any Tailscale classification needed for marking/SNAT and before the final drop path. Do not insert it at the head by assumption. If the live chain has no safe point that preserves Tailscale's classification and still enforces the pilot drop, stop and redesign before deployment. That chain will:

1. Accept only packets entering `tailscale0` from `100.70.142.17/32` and routed to `wlnh0`.
2. Drop any other IPv4 egress for that source, so a missing veth/table route cannot fall through to SethLinux's normal route.
3. Accept only established/related return traffic from `wlnh0` to `tailscale0`.
4. Return all unrelated traffic to the existing Docker and Tailscale rules.

An IPv6 `WALNUTS_PILOT6` chain/jump will drop forwarding from PC-STREAM's Tailscale IPv6 source. SethLinux's IPv6 forwarding remains `0`. The host hook must be placed so the drop applies before any accept path; exact current chain layout is a privileged preflight gate.

Inside `vpnbook`, create a pilot-owned filter/NAT chain and exact jump(s), only after confirming the active namespace backend and existing VPNBook kill-switch. Permit the veth source only toward `wg-vpn`, permit established returns, masquerade only that veth source on `wg-vpn`, and drop any other pilot egress. Preserve `10.104.12.196/32`, its default route, both existing DNS resolvers, and the current VPNBook service.

The veth subnet and namespace NAT are separate from the Tailscale SNAT. Expected flow: Tailscale's existing postrouting SNAT translates the original client source to the host-veth address; namespace NAT translates that address to the WireGuard interface for VPNBook egress. Both conntrack return translations must be observed in a controlled test. If live rules do not SNAT to `169.254.240.1`, stop and revise the plan; do not work around it by allowing the original client source through the host default route.

### Routing and priorities

- Host route table: `198`, with `default via 169.254.240.2 dev wlnh0`.
- IPv4 RPDB priority `5000`: `iif tailscale0 from 100.70.142.17/32 lookup 198`.
- IPv4 fail-closed priority `5001`: same ingress/source selector to `unreachable`.
- IPv6 fail-closed priority `5000`: `iif tailscale0 from fd7a:115c:a1e0::7f3b:8e11/128 unreachable`.
- Existing Tailscale priorities 5210–5270 remain intact. Do not modify table 52, Tailscale marks, Docker bridges, or SethLinux's main/default table.
- Proposed interface names: `wlnh0` on host and `wlnn0` inside `vpnbook`. Proposed veth `/30`: `169.254.240.1/30` and `169.254.240.2/30`. Confirm no overlap or interface-name collision immediately before use.

The IPv6 rule is defense in depth, not the sole client leak control. A Windows client may have local IPv6 paths or DNS outside the exit-node route. VPNBOOK mode must also enforce a PC-STREAM local firewall kill switch for public IPv6 and non-approved DNS, with LAN bypass disabled. If the client's IPv6 kill switch cannot be installed and verified, VPNBOOK mode is not enabled. DIRECT mode removes only the pilot client block and restores the captured PC-STREAM DNS baseline.

## Tailnet authorization

Use a dedicated `tag:pc-stream-vpnbook-pilot`, owned only by tailnet admins, on the verified PC-STREAM node. The narrow grant required for exit-node use is:

```json
{
  "src": ["tag:pc-stream-vpnbook-pilot"],
  "dst": ["autogroup:internet"],
  "ip": ["*"]
}
```

Merge this into the existing policy; do not replace the policy. Add policy tests proving PC-STREAM can reach `autogroup:internet` and representative non-pilot devices cannot. Before enabling, inspect all existing grants for broader access to `autogroup:internet`; an additive grant cannot revoke a broader grant. Tailscale policy cannot select a particular exit node: the grant permits that tagged device to use any available exit node. The local SethLinux firewall and single-device routing rule still limit this adapter to PC-STREAM. The existing policy, device tag assignment, and device approval state have not been read, so tailnet-policy approval is a deployment gate.

## DNS mode behavior

- VPNBOOK mode sets PC-STREAM's active DNS to `1.1.1.1` and `8.8.8.8`; queries must traverse the selected exit node, reach the namespace only through `wg-vpn`, and fail when the tunnel is down. Do not use Pi-hole or Cloudflare DNS until their upstream path is proven to remain inside this namespace tunnel.
- DIRECT mode restores the exact DNS configuration captured from PC-STREAM before the pilot. That value is not yet known; do not guess it from SethLinux's DNS configuration.
- Verify with fresh unique names and packet/route evidence in both modes. A successful lookup alone does not prove which resolver handled it.

## Persistence and fail-closed startup

Install one dedicated `walnuts-pilot.service` only after approval. It must run after `vpnbook.service`, Tailscale, and network-online; confirm the namespace, `wg-vpn`, fresh WireGuard handshake, route, namespace kill-switch, and policy-file identity before enabling any pilot allow path. If any prerequisite fails, the service must leave pilot IPv4/IPv6 drops active and must not advertise the exit node. The policy lookup has an unreachable fallback. Do not persist changes to `net.ipv4.ip_forward` or `net.ipv6.conf.all.forwarding`; the current values already meet the proposed IPv4-only host path. On boot, install drop guards before any allow jump. A reboot-order rehearsal must prove that an unavailable namespace/tunnel cannot expose PC-STREAM traffic to `eno1`.

The service must have a dedicated state file recording only pilot-owned object identifiers and prior client DNS/firewall state. Stop/removal must require exact identity matches; it must never flush a shared chain or table. If Tailscale or VPNBook is unavailable, leave the exit-node advertisement disabled or withdraw only this pilot's advertisement.

## Preflight gates before deployment approval

1. Refresh PC-STREAM identity/address and online state; capture its baseline IPv4/IPv6 egress, DNS, Windows firewall profile, and local IPv6 routes.
2. Obtain privileged read-only snapshots of `iptables-save` filter/nat, `ip6tables-save`, `nft list ruleset`, namespace routes/firewall/NAT, `wg show`, and the VPNBook unit. Confirm exact Tailscale forward and SNAT matches, chain order, and translated veth source.
3. Reconfirm current host IPv4/IPv6 forwarding values and all route tables/rule priorities; confirm table 198, priorities 5000/5001, veth names and `/30` are available.
4. Review active Tailscale peer routes, admin approval, device tag, and full tailnet grants. Test policy so only the tagged PC-STREAM source gains `autogroup:internet` access; remove or narrow any pre-existing broader grant only through an explicitly reviewed policy diff.
5. Record current DNS behavior on PC-STREAM and prove both namespace resolvers are reachable only through `wg-vpn`.
6. Baseline SethLinux SSH/Tailscale, main route, Cloudflare, Pi-hole, Minecraft, Docker, and VPNBook. Review FORWARD dependencies so the single custom jump preserves all unrelated traffic.
7. Validate exact install/remove commands and a timed rollback against those snapshots. Do not advertise the exit node until the namespace path, client kill switch, DNS, and rollback are verified.

**Current blocker:** item 2 cannot be completed with the current unprivileged Gateway session. Read-only attempts to inspect iptables/nft rules returned `Permission denied`; do not change sudo, alternatives, or firewall permissions as a workaround. The known Gateway trusted-executable limitation must be resolved through its supported path or an operator-provided privileged read-only capture. No other machine or Gateway server is required.

## Deployment sequence after the gates and explicit approval

1. Recheck the approved snapshot hashes and values. Arm a timed rollback with a separate, verified SSH/Tailscale management path.
2. Install boot-time fail-closed drop guards and the Windows VPNBOOK-mode IPv6/DNS kill switch. Confirm direct mode remains selectable and capture exact undo state.
3. Create only the host/namespace veth, dedicated route table and source rules; leave host main routes, Docker/Tailscale chains, and service configurations intact.
4. Add only the pilot-owned IPv4/IPv6 and namespace NAT rules. Verify ruleset diffs contain no other changes. Test namespace resolver traffic and public IPv4 through `wg-vpn` before advertising.
5. Add/validate the narrow tailnet policy grant and tests, tag PC-STREAM, then advertise SethLinux as an exit node and obtain its admin approval. Explicitly select SethLinux on PC-STREAM with local LAN access off.
6. Check DIRECT then VPNBOOK egress/DNS/IPv6 and service baselines. Repeat with the namespace tunnel deliberately unavailable in the controlled window. Keep rollback armed until all checks pass.

## Health checks and immediate rollback triggers

Require all of these on every switch and periodically while VPNBOOK is selected:

- PC-STREAM Tailscale IPv4/IPv6 identity matches the approved snapshot.
- SethLinux host route remains `default via 192.168.1.1 dev eno1`; protected services remain healthy.
- `vpnbook` and `wg-vpn` are up; WireGuard handshake is no older than 180 seconds.
- DNS query succeeds using one of the two approved namespace resolvers and is observed through `wg-vpn`.
- VPNBOOK mode public IPv4 equals the freshly verified VPN egress (`147.135.15.16` is only the prior value); public IPv6 fails at both client and server boundaries.
- DIRECT mode has no selected exit node, restores captured client DNS, and sees the freshly verified normal egress (`198.29.53.14` is only the prior value).
- With the tunnel down, PC-STREAM has no public IPv4/IPv6 path; traffic does not escape through `eno1`.

Any mismatch immediately selects no exit node on PC-STREAM, restores its DNS/firewall baseline, withdraws only the newly created exit advertisement, removes only the exact pilot rules/table/veth/service, and verifies normal route and protected services. Restore sysctls only if the pilot changed them; this plan proposes no sysctl change. Stop rollback if an object differs from the captured snapshot.

## Offline validation

`config/pilot.example.toml` includes the current PC-STREAM tailnet addresses, previously observed namespace DNS, and observed firewall backend while leaving unverified deployment evidence false or blank. `walnuts pilot-plan config/pilot.example.toml` must continue to block and emit no apply actions. The Python planner remains offline-only. This change set does not grant deployment approval.
