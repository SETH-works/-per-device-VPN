# Phase 1 — PC-STREAM Tailscale-to-VPNBook pilot

**Status: offline design only.** No exit-node advertisement, host route/firewall/DNS change, router change, service restart, or PC-STREAM switch has been performed. This document is a pre-deployment plan; live changes require a separate explicit approval after all blockers below are cleared.

## Packet path and separation

```text
PC-STREAM (explicitly selects SethLinux exit node)
  -> encrypted Tailscale peer traffic
SethLinux tailscale0
  -> ingress-and-source-specific policy rule + isolated RPDB table
host veth wlnh0 <-> namespace veth wlnn0
  -> Tailscale forward/SNAT path (must translate source to wlnh0 address)
  -> vpnbook namespace (connected veth return route)
  -> namespace default route wg-vpn
  -> namespace-scoped IPv4 masquerade
  -> VPNBook exit 147.135.15.16
```

Advertising SethLinux as an exit node only makes Tailscale an ingress path for a client that explicitly selects it. It does not connect Tailscale packets to `vpnbook`. The host needs forwarding enabled; an ingress-and-source-specific policy rule sends only packets from PC-STREAM's verified Tailscale IPv4 address to a veth. Tailscale's Linux forward path marks and handles forwarded traffic; its live post-routing behavior must be inspected and verified to translate the source to the host-veth address before packets enter `vpnbook`. The namespace then uses its connected veth route for replies, while namespace-scoped NAT sends public traffic through `wg-vpn`. This two-stage conntrack/NAT return path is a strict precondition, not an assumption. The host main default route remains via Ethernet.

The adapter plans an ingress-interface-and-source-specific RPDB rule (`iif tailscale0` plus PC-STREAM's verified IPv4 address), a dedicated route table, a second unreachable rule, and a separate IPv6 unreachable rule. This avoids depending on a packet mark or colliding with Tailscale's observed `0x80000/0xff0000` marks. If the namespace route vanishes, matching IPv4 traffic must hit the unreachable rule rather than continue through SethLinux's main route. Host firewall rules are intended in a separate `inet walnuts_pilot` table and must only drop/allow the pilot's forwarded flow. Namespace rules are intended in a separate `inet walnuts_vpnbook_pilot` table and must constrain only the new veth flow. Existing tables and Tailscale-managed chains are not replaced.

This flow is conditional on verifying the live firewall backend, Tailscale netfilter mode and SNAT-to-veth behavior, existing chain priorities and forward dependencies, host forwarding sysctls, namespace route/kill-switch, noncolliding /30, table id, rule priorities, and firewall table names. These facts are not currently verified. The design must be revised if live packet source identity, SNAT, or rule order conflicts.

## DNS and IPv6 policy

- VPN mode uses an explicitly approved resolver whose address is reachable through `wg-vpn`; the pilot must verify the DNS exchange from PC-STREAM and confirm its egress is the tunnel. DIRECT mode restores the exact PC-STREAM DNS baseline captured before the pilot. Do not assume SethLinux's Pi-hole is safe to use in VPN mode: its upstream path is currently unknown. Do not change tailnet or host DNS during this offline phase.
- Disable PC-STREAM's local-LAN exit-node bypass during VPN mode. Do not add a LAN DNS exception unless its upstream is proven to use the VPNBook tunnel.
- The verified VPNBook exit is IPv4 only. Therefore VPN-mode IPv6 must fail closed. Host forwarding may need IPv6 enabled for Tailscale exit-node advertisement, but an isolated firewall drop for this client's IPv6 forwarded traffic must take effect before any egress. Prove both IPv4 and IPv6 behavior at PC-STREAM. If an IPv6 tunnel later becomes verified, re-review this policy.
- Tailscale's exit-node mechanism and the local VPNBook namespace are separate routing layers. Current Tailscale documentation requires an advertised and approved exit node, client-side opt-in, IP forwarding, and permission to use `autogroup:internet`; a broad grant would expose the exit node to more than the pilot device. Restrict access with a verified PC-STREAM device identity/policy, and locally fail closed for any other forwarded client.

## Pre-deployment blockers

The offline template at `config/pilot.example.toml` is intentionally incomplete. `walnuts pilot-plan config/pilot.example.toml` should report blockers until all live values and evidence are supplied. Current blockers include:

1. PC-STREAM's verified Tailscale IPv4 and device identity.
2. PC-STREAM's verified Tailscale IPv6 address for a client-specific IPv6 unreachable rule.
3. A DNS resolver selected for VPN mode and proof it is reached only through `wg-vpn`, plus PC-STREAM's baseline resolver for DIRECT mode.
4. Namespace interface/routes, `wg-vpn` address and fresh handshake, VPNBook kill-switch, and in-namespace public IPv4 evidence.
5. Host IPv4/IPv6 forwarding values, firewall backend and Tailscale netfilter mode, existing rule/chain priorities, Tailscale SNAT-to-veth behavior, and current forwarding consumers.
6. Collision-free veth subnet, policy table id, consecutive RPDB priorities, and host/namespace nftables table names.
7. Exact tailnet grant limiting exit-node use to PC-STREAM and the observed state of existing Tailscale exit/subnet routes.
8. A complete pre-change health baseline for SethLinux's default route, SSH/Tailscale, Cloudflare, Pi-hole, Minecraft, Docker, and VPNBook.
9. A persistent fail-closed boot guard ordered before exit-node traffic is allowed to forward, plus a controlled reboot-order verification that preserves Tailscale management access.

The previous Phase 0 evidence showed the main IPv4 route via `192.168.1.1` on `eno1`, Tailscale rules at priorities 5210–5270 using mark `0x80000/0xff0000`, a `vpnbook` namespace, and an enabled `vpnbook.service`. It did not show the namespace internals or firewall policy. Do not treat template values `route_table=198`, `rule_priority=5000`, or the suggested veth names/addresses as reserved until each has been checked live.

## Ordered deployment plan (approval required)

1. Capture exact sysctls, `ip rule` and all relevant route tables, firewall backend/rules, Tailscale state and policy, namespace interfaces/routes/firewall, service state, DNS resolver behavior, and protected-service checks. Save private, redacted pre-change snapshots. Confirm no conflicts with Docker or other Tailscale forwarding.
2. Prepare and validate a rollback script and arm a timed rollback before applying changes. The rollback must target only the pilot tables, rule priorities, route table, veth pair, and forwarding values changed by this pilot.
3. Install and verify persistent fail-closed guards first. Create the dedicated veth pair and addresses; enable only required forwarding; add the ingress-and-source-specific host policy lookup, IPv4 unreachable fallback, and client-specific IPv6 unreachable rule; add scoped host/namespace nftables rules and namespace-only tunnel NAT. Do not change SethLinux's main/default route.
4. Verify the route and firewall dry-run against the live state; test locally from the namespace that DNS and public IPv4 egress use `wg-vpn` before enabling Tailscale exit-node advertisement.
5. Advertise SethLinux as an exit node, approve it for the tailnet, and restrict exit-node permission to PC-STREAM. On PC-STREAM explicitly select SethLinux with local LAN access disabled. Its no-exit selection is the explicit DIRECT mode.
6. Run the acceptance checks below. Any mismatch triggers immediate PC-STREAM exit-node deselection and exact-object rollback. Keep the timed rollback armed until the complete check set passes.

### Acceptance checks

- DIRECT: PC-STREAM selects no exit node, restores its captured direct-mode DNS resolver, and sees `198.29.53.14`; SethLinux's main route is unchanged.
- VPNBOOK: PC-STREAM explicitly selects SethLinux and sees `147.135.15.16`.
- DNS: fresh unique lookup succeeds using the approved tunnel resolver in VPNBOOK mode, and a separate lookup succeeds using the captured baseline resolver in DIRECT mode; observation confirms each resolver and egress path.
- IPv6: public IPv6 from PC-STREAM has no egress in VPNBOOK mode.
- Fail closed: in a controlled test, stopping only the tunnel path makes PC-STREAM lose public IPv4 and IPv6; there is no fallback through SethLinux Ethernet. Other tailnet clients are not redirected or disrupted.
- Recovery: restoring the tunnel permits a fresh health check and the PC-STREAM mode can be switched back to DIRECT and VPNBOOK.
- Protected-service baseline, SethLinux SSH/Tailscale reachability, and host main route remain unchanged.

## Rollback order

1. Set PC-STREAM's exit node to None.
2. Withdraw only the exit-node advertisement created for this pilot; preserve any pre-existing advertised routes.
3. Remove the exact pilot IPv4 lookup/fallback and IPv6 unreachable rules, plus the route table entries.
4. Delete only host table `inet walnuts_pilot` and namespace table `inet walnuts_vpnbook_pilot`; do not flush shared tables/chains.
5. Delete host veth `wlnh0` (which removes its peer) only after route guards and exit-node advertisement are safely removed or redirected.
6. Restore the captured forwarding sysctl values only if this pilot changed them and no other service now depends on forwarding.
7. Verify DIRECT egress, original host default route, SSH/Tailscale, Cloudflare, Pi-hole, Minecraft, Docker, and existing VPNBook baseline.

The rollback must stop and request review if an expected object differs from the pre-change snapshot; never remove an object by a broad flush or guessed name.

## Offline plan tool

`walnuts pilot-plan <toml>` validates a typed plan and emits blockers until every required observation is asserted. With a complete plan it prints ordered configuration, rollback, and acceptance actions. It is deliberately non-executable and has no apply command. Its output is not deployment approval.

Current official references: [Tailscale exit nodes](https://tailscale.com/docs/features/exit-nodes), [Tailscale netfilter modes](https://tailscale.com/docs/reference/netfilter-modes), and [Tailscale IP-forwarding requirements](https://tailscale.com/docs/reference/troubleshooting/network-configuration/ip-forwarding-errors-advertise).
