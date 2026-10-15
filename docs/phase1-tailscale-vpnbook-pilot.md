# Phase 1 — PC-STREAM Tailscale-to-VPNBook pilot

**Status: offline design only.** No route, firewall, DNS, tailnet policy, advertisement, or client setting has been changed.

Use the [current operator runbook](phase1-operator-runbook.md) as the authority. Windows activation is blocked pending a validated independent underlay boundary. The [earlier deployment change set](phase1-deployment-change-set.md) retains historical server context and cannot authorize activation. The sample TOML and `walnuts pilot-plan` remain a dry-run gate and cannot apply changes.

The packet path is explicit: PC-STREAM selects SethLinux as an exit node; an ingress/source-specific host rule sends only its IPv4 traffic through a dedicated veth to `vpnbook`; that namespace sends the traffic through `wg-vpn` and applies namespace-only NAT. Tailscale exit-node advertisement alone does not connect its traffic to the namespace. Exact Tailscale SNAT/forwarding rules still require privileged read-only inspection.

The live evidence shows the host uses `iptables-nft`, IPv4 forwarding is on, IPv6 forwarding is off, and the main route remains via `192.168.1.1` on `eno1`. The proposal preserves the main route, Docker, Tailscale, Pi-hole, Cloudflare, Minecraft, and VPNBook. IPv6 must fail closed on both the host and PC-STREAM; DNS is explicit in each mode and must be verified end to end.

Tailnet policy can grant `autogroup:internet` access to the uniquely tagged PC-STREAM device and tests can deny the other devices. Tailscale policy cannot restrict that grant to one particular exit node, so the host-side source-specific firewall remains necessary.

**Deployment is blocked** until privileged Tailscale/namespace firewall and NAT snapshots, namespace health and kill-switch, client DNS/IPv6 baselines, tailnet policy review, and all preflight checks in the change set are complete. After that, the exact plan still requires the user's approval before live changes.
