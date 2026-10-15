# Project Walnuts Phase 1 operator runbook

**Windows activation is blocked.** This release supports read-only audit, blocked dry runs and tightly gated recovery. It cannot establish the required PC-STREAM underlay boundary. Do not execute the earlier deployment sequence from commits 83f44d8 or cbe8788. Neither a clean rule inventory nor a configuration switch can enable Arm, VPNBOOK or Verify in this release.

## Protection mechanism decision

Windows Defender Firewall's explicit allows override its default outbound Block. An explicit Ethernet Block overrides conflicting transport allows regardless of their specificity. Consequently, neither the previous default-Block arrangement nor blanket-Block-plus-allow exceptions expresses this pilot's required separation while preserving unrelated rules. Program/service rules lack a general complement meaning “all applications except this service.” Enumerating every current process is not safe against newly installed processes.

The implemented correction is an unconditional activation gate and an effective-policy audit. It does not introduce an enforcement backend or claim to stop traffic from a previously activated legacy client. A legacy protected journal is DEGRADED, because its actual protection cannot be established.

The smallest proposed alternative is a user-mode native WFP management helper using ordinary built-in filters in a Walnuts-owned provider and sublayer. This is a design candidate requiring review and isolated Windows testing before implementation. It needs no custom kernel callout or driver. Do not silently substitute another VPN/firewall product.

References: [Microsoft rule precedence and policy merging](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules), [WFP arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration), [WFP conditions](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-), [Tailscale Windows service implementation](https://github.com/tailscale/tailscale/blob/main/cmd/tailscaled/install_windows.go).

## Proposed helper contract — not implemented

- Validate the SCM Tailscale executable, Authenticode signature, protected installation ACLs, running process image and service identity. tailscale.exe is a CLI; the daemon is resolved from SCM rather than inferred from a filename.
- Use a private sublayer whose higher-weight service-specific exceptions are evaluated before its lower-weight underlay block. A matching permit skips the lower block in that same sublayer; a blanket Defender block plus a Defender allow does not have that behavior. Soft permits must not override other providers' security blocks. Check hard permits, IPsec and third-party providers during arbitration review; weights alone do not prove isolation.
- Bind filters to reviewed adapter identities/LUIDs, not aliases or mutable indexes alone. Cover IPv4 and IPv6 ALE connect, reauthorization/previously established flows, and the actual outbound/forwarding layers traversed by this Windows Tailscale build. Verify that the conditions exist together at the selected layers. The exact layer/filter matrix is an open design task.
- Allow authenticated Tailscale service traffic over UDP for direct peers, STUN and changing endpoints, plus TCP/443 for coordination and DERP. No fixed peer allowlist survives roaming. This is a process/service-restricted transport envelope, not a public exception for applications or arbitrary copies of tailscale.exe. Prove service attribution works for the actual daemon's sockets.
- Allow only demonstrated DHCP maintenance scoped to the reviewed interface, DHCP service and ports. Document DNS bootstrap for the daemon: broad svchost/dnscache UDP/53 exceptions are forbidden. If this Tailscale build cannot bootstrap without such a bypass, stop and solve that dependency in the lab.
- Preserve ARP and required IPv6 neighbor discovery/link-local mechanisms. Block native public IPv6 and IPv6 tunneling by unapproved processes, including protocol 41, Teredo/UDP and application tunnels. Blocking only protocol 41 is insufficient. Do not globally disable IPv6 or modify Hyper-V.
- Persist blocking filters across helper crashes, service restarts and host boot. Dynamic-session filter deletion on process exit would fail open and is unacceptable. Transactional filter updates, boot-time availability, BFE interruption and adapter replacement must have demonstrated failure behavior. Unknown new underlays must not create a bypass.
- Preserve host Windows management and Hyper-V configuration. Separately determine the scope of forwarded guest traffic; do not claim an Ethernet interface rule proves Hyper-V isolation. If host/guest paths cannot be separated without unwanted disruption, stop.
- Store exact provider/sublayer/filter GUIDs, object shapes and adapter identity before mutation. Reconcile actual WFP objects, never trust only a journal. Remove only verified owned objects on explicit confirmed DIRECT.

No filter weights, driver, helper service or privileged installer are shipped by this correction. The above is a bounded proposal, not a deployment-ready WFP specification.

## Read-only firewall conflict preflight

From an elevated PowerShell window on PC-STREAM after copying the reviewed repository files and private configuration:

```powershell
.\client\walnuts-client.ps1 -Mode Audit -ConfigPath .\client\pilot-client.json |
  Set-Content -Encoding utf8 .\pc-stream-firewall-audit.json
.\client\walnuts-client.ps1 -Mode Status -ConfigPath .\client\pilot-client.json
.\client\walnuts-client.ps1 -Mode Arm -PlanOnly -ConfigPath .\client\pilot-client.json
.\client\walnuts-client.ps1 -Mode VPNBOOK -PlanOnly -ConfigPath .\client\pilot-client.json
```

Audit and blocked activation plans return exit code 2 intentionally. The optional output file is an operator-created diagnostic artifact; the controller never changes firewall, DNS, routes or services in these modes.

Audit reads ActiveStore with policy-source tracing and associated application, service, port, address, alias and type filters. It preserves all filters in JSON. Counts reduce console noise; each row explains its classification:

| Category | Meaning |
| --- | --- |
| ConfirmedBypassRisk | An explicit enabled outbound allow can match Ethernet/public destinations. This confirms a rule-scope risk, not a successful live bypass. |
| PotentialBypass | A required filter could not be read/expanded, or an explicit block could interrupt transport. Stop preflight and review. |
| Restricted | Disabled/inbound, interface-excluded, wired-excluded or explicitly local-only address scope; this row cannot itself authorize public Ethernet traffic. |
| ApprovedUnderlayException | Candidate rule matches the strict SCM service-path/service/adapter/protocol envelope. Not evidence of signature trust, packet attribution, complete transport availability or installed enforcement. |

Profile restrictions are retained rather than assumed harmless: Private, Public and Domain can change. Dynamic address keywords and unresolved ranges fail preflight conservatively. An explicit block is reported as a potential transport conflict; an unrelated allow is never declared harmless merely because another block exists. Local-policy merge failures, missing profiles/interfaces, service absence and query errors block readiness. Hyper-V firewall and third-party WFP filters are outside NetSecurity's full visibility and require separate lab capture.

Read-only supplementary inspection:

```powershell
Get-NetAdapter | Format-Table Name,InterfaceDescription,InterfaceGuid,ifIndex,Status
Get-NetIPInterface | Format-Table InterfaceAlias,AddressFamily,InterfaceMetric,Dhcp
Get-DnsClientServerAddress
Get-CimInstance Win32_Service -Filter "Name='Tailscale'" |
  Select-Object Name,PathName,State,ProcessId
Get-NetFirewallProfile -PolicyStore ActiveStore |
  Select-Object Name,Enabled,DefaultOutboundAction,AllowLocalFirewallRules
& "$env:ProgramFiles\Tailscale\tailscale.exe" debug prefs
& "$env:ProgramFiles\Tailscale\tailscale.exe" status --json
```

Do not run destructive failure probes or change profiles to complete this preflight. Refresh the historical PC-STREAM IPv4 100.70.142.17, IPv6 fd7a:115c:a1e0::7f3b:8e11, Ethernet 192.168.1.12 and DHCP DNS 192.168.1.1. The SCM path is authoritative over the example CLI path.

## DNS and IPv6 acceptance requirements

The planned DNS configuration remains approved resolvers 1.1.1.1 and 8.8.8.8 on the detected Tailscale virtual interface with accept-dns=false; Ethernet stays DHCP managed. Activation is disabled, so this release does not apply that configuration. Tailscale's default exit-node DNS proxy can originate queries on SethLinux outside the client-specific source route, which is why accepting DNS blindly is unsuitable for this architecture.

Resolver address configuration, route metrics, a cached response or a successful Resolve-DnsName call cannot prove DNS egress. In the isolated test environment, use unique queries under an operator-controlled wildcard domain and simultaneous captures on physical Ethernet, Tailscale and namespace wg-vpn. Include DNS Client UDP/TCP 53, application DoH/TCP 443, QUIC/UDP 443, IPv6 DNS, native IPv6, protocol 41 and UDP tunneling. Ordinary DNS/DoH must not pass directly on physical Ethernet; only encrypted authenticated daemon transport should do so. Essential link-local activity must remain operational.

ARMED_BLOCKED must select no exit node and permit no ordinary public application egress despite working Tailscale coordination. VPNBOOK must select SethLinux 100.112.153.81 and show VPNBook egress; tunnel or daemon loss must never restore ISP traffic. Endpoint roaming/restart must either preserve the boundary or remain blocked with accurate status. A monitor that notices a leak after it happened is not a kill switch.

## Evidence classification

Offline verified: behavioral synthetic-filter classification, service-command parsing, unconditional activation gate execution with side-effect traps, Python core tests and PowerShell parsing. Test counts are recorded in the release handoff. These are not WFP packet tests.

Previously observed: the Windows rule examples in the request, host/namespace/Tailscale baselines and prior egress observations. They were not refreshed during this repository pass.

Not verified: native WFP enforcement, live DNS path, DERP/direct transport under protection, established-flow blocking, adapter/profile changes, Hyper-V behavior, reboot, BFE interruption and deliberate tunnel loss. No suitable isolated Windows packet-test environment was used.

## Later lab installation and test sequence — requires a reviewed implementation

1. Review the bounded helper design, exact filter matrix, ownership/rollback plan and persistent failure behavior. Keep deployment blocked until the helper exists and is audited.
2. Use an isolated Windows VM with an equivalent Tailscale version, service, firewall rules, multiple adapters and Hyper-V topology where relevant. Snapshot it; preserve out-of-band management. Approval applies to that lab only.
3. Stage files only; capture effective firewall/WFP state, adapter identities, service image/signature, DNS, profiles and active flows. Do not change unrelated policies.
4. Install the future owned block boundary transactionally before changing DNS or selecting an exit. Confirm existing explicit allows cannot bypass it and that UDP direct transport and TCP DERP still work.
5. Test ARMED_BLOCKED, native/encapsulated IPv6, DNS Client, DoH, pre-existing sockets, profile changes, daemon restart, endpoint roaming, adapter change, helper crash, BFE/firewall reload and reboot.
6. With server readiness separately verified, select the exit and capture both NAT stages plus DNS and egress. Stop on any unexpected physical application packet, management interruption, unresolved classification or ownership mismatch.
7. Demonstrate tunnel loss with no ISP fallback, recovery without automatic DIRECT, and explicit baseline restoration. Obtain separate production approval only after reviewing the concrete results.

There is no usable production installation command in this release. Do not bypass the activation gate, revert to the old controller or alter unrelated firewall rules to pass preflight.

## Explicit DIRECT and emergency recovery

Recovery is owner-authorized only. It never runs after a protected-mode error automatically. Existing legacy rules are retained. The old baseline lacks owned rule GUIDs, so if legacy rules exist the controller stops before all network writes and requires a reviewed exact-ID manual recovery plan. Unknown/corrupt journals, installation-path changes and stale Tailscale interface indexes also stop recovery. Do not create a fresh baseline from an already partially protected machine.

For a valid version-2 baseline with no legacy rules remaining, preview:

```powershell
.\client\walnuts-client.ps1 -Mode DIRECT -PlanOnly -ConfirmDirect -ConfigPath .\client\pilot-client.json
```

Only during a separately approved owner recovery window:

```powershell
.\client\walnuts-client.ps1 -Mode DIRECT -ConfirmDirect -Confirm -ConfigPath .\client\pilot-client.json
.\client\walnuts-client.ps1 -Mode EmergencyDirect -ConfirmDirect -EmergencyPhrase 'I UNDERSTAND THIS DISABLES VPN PROTECTION' -Confirm -ConfigPath .\client\pilot-client.json
```

Use one operation as appropriate. Both have the same identity/ownership gates. DIRECT clears the exit selection, restores DHCP Ethernet DNS and captured Tailscale DNS, then restores the captured accept-dns preference and firewall profiles. Tailscale DNS acceptance is restored after manual DNS restoration so the captured manual values cannot overwrite Tailscale's fresh accepted configuration. Any failure stops immediately; do not report success from the journal alone. Confirm observed DHCP provenance, no exit node, original profile settings and intentional ISP egress afterward. Index reuse cannot be conclusively excluded by a legacy alias/index journal; manual identity review remains required.

## SethLinux protections and read-only validation

The Linux implementation and systemd units are unchanged by this correction. Preserve its owned nftables forward guard at priority 10, source rule/table 198 and unreachable fallbacks. Tailscale's early ACCEPT cannot cancel a later hook drop, but actual two-stage SNAT/conntrack return behavior remains a deployment blocker.

Using a reviewed staging copy and private configuration, read-only commands are:

```sh
sudo env PYTHONPATH=/opt/walnuts/src /usr/bin/python3 -m walnuts.cli server-preflight /etc/walnuts/pilot.toml
sudo env PYTHONPATH=/opt/walnuts/src /usr/bin/python3 -m walnuts.cli server-dry-run /etc/walnuts/pilot.toml
tailscale status --json
tailscale debug prefs
ip -4 rule show
ip -6 rule show
ip -4 route show default
sudo iptables-save -t filter
sudo iptables-save -t nat
sudo nft list ruleset
sudo ip netns exec vpnbook nft list ruleset
sudo ip netns exec vpnbook conntrack -L
```

Do not set evidence true merely to pass preflight. Do not install/reload guard units, advertise an exit node, change policy, restart services or activate the client in this pass. Gateway's sudo trusted-path limitation remains unresolved; use the owner's normal sudo path for approved privileged reads, without replacing sudo or alternatives.

LAN recovery remains SSH to seth@192.168.1.41 from an independently reachable LAN device. Guard failure can intentionally prevent tailscaled startup. Repair verified missing owned guard objects from LAN after reviewing the failure; never flush shared rules or remove the guard while a client may depend on it. A live LAN recovery/boot rehearsal is still outstanding.
