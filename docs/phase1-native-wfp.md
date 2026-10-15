# Native WFP lab candidate

Production remains blocked. This implementation calls the real Windows WFP management APIs, but no live engine installation or packet test has been performed in this development session. It is not a fully fail-closed production release. Do not install it on STREAM or SethLinux.

## Source, build and trust boundary

`client/wfp/` is a Windows x64 C# executable with explicit native interop; there is no driver, callout, third-party firewall or NuGet dependency. The available compiler/runtime is .NET 11 RC. The built framework-dependent executable therefore requires the matching .NET 11 runtime; this preview dependency is an additional production blocker. The Python core and Linux adapter are unchanged.

Offline, from the repository root:

```powershell
.\client\wfp\build.ps1
Invoke-Pester .\client\tests\walnuts-firewall.Tests.ps1
Invoke-Pester .\client\tests\walnuts-wfp.Tests.ps1
$env:PYTHONPATH='src'
python -m unittest discover -s tests
```

The build script runs only `self-test`; it never opens BFE. Output is in `client/wfp/bin/Release/net11.0/`. Copy all four runtime files together. The controller pins SHA256 for the EXE, DLL, deps JSON and runtimeconfig JSON; the sample client configuration must gain `HelperSha256` and a `HelperFiles` object containing the three companion filename/hash pairs. Do not trust a successful apphost launch as proof that the managed DLL is trusted. The build is unsigned; a reviewed hash bundle is used for the lab. Review Authenticode on Tailscale separately, then pin its executable hash.

Observed offline validation for this change: build succeeded with zero warnings/errors; 53 native self-test assertions, 53 Python tests and 57 Pester tests passed; all PowerShell files parsed. Python invokes the native self-test as one test, so these counts are not a count of independent packet tests. No real WFP engine installation or packet test was run. The existing production controller gate was exercised with side-effect traps.

Mutations require an elevated local session, protected Program Files binaries, protected ProgramData configuration, matching deployment GUID and VM hostname, a recognized virtual-machine BIOS identity and automatic guard-service registration. STREAM is explicitly rejected by native configuration validation and PowerShell orchestration. The VM test check is an accidental-use barrier, not isolation from a malicious administrator.

The helper reads only `%ProgramData%\WalnutsWfp\lab.json` and does not execute shell commands. Its configuration rejects unknown JSON properties and invalid modes/IDs/hash formats. Native provider metadata records the reviewed configuration, deployment ID, adapter GUIDs/LUIDs, service path/SID and app-identity blobs. File trust checks reject reparse points and untrusted owners/writers. Only SYSTEM and Administrators receive object DACL access. Local administrators, SYSTEM, the Windows installation/runtime and the correctly pinned Tailscale service are trusted.

## Exact filter matrix

Provider GUID: `d8725958-c836-49c0-8c93-a77977077f91`.
Sublayer GUID: `33191e96-ac76-43a1-baf1-116bbd91333e`, weight `0x7000`.
Each filter GUID is derived from SHA256(owner-version + deployment GUID + rule name), first 16 bytes. No object is identified for removal by display name.

Every installed filter has `FWPM_FILTER_FLAG_PERSISTENT=1`. The provider and sublayer are persistent too; the provider binds to automatic service `WalnutsWfpGuard`. No dynamic-session lifetime, callout fallback, hard-permit flag or boot-time flag is used.

| Rule | Layer | Weight | Action | All required conditions (EQUAL) |
| --- | --- | ---: | --- | --- |
| deny-v4 | ALE_AUTH_CONNECT_V4 | 100 | BLOCK | None: default for every interface/profile/application |
| deny-v6 | ALE_AUTH_CONNECT_V6 | 100 | BLOCK | None |
| daemon-udp-v4/v6 | Corresponding ALE_AUTH_CONNECT | 500 | soft PERMIT | ALE_APP_ID = pinned SCM image app blob; ALE_USER_ID = service-SID security descriptor; IP_NEXTHOP_INTERFACE = reviewed underlay LUID; IP_PROTOCOL = UDP |
| daemon-tcp443-v4/v6 | Corresponding ALE_AUTH_CONNECT | 500 | soft PERMIT | Same image/SID/underlay constraints; TCP; remote port 443 |
| dhcp-v4 | ALE_AUTH_CONNECT_V4 | 500 | soft PERMIT | svchost app blob AND Dhcp service SID; reviewed underlay LUID; UDP; local 68; remote 67 |
| loopback-v4 | ALE_AUTH_CONNECT_V4 | 300 | soft PERMIT | Remote 127.0.0.0/8 |
| loopback-v6 | ALE_AUTH_CONNECT_V6 | 300 | soft PERMIT | Remote ::1/128 |
| linklocal-icmp6 | ALE_AUTH_CONNECT_V6 | 300 | soft PERMIT | Remote fe80::/10; ICMPv6; reviewed underlay LUID |
| multicast-icmp6 | ALE_AUTH_CONNECT_V6 | 300 | soft PERMIT | Remote ff02::/16; ICMPv6; reviewed underlay LUID |
| tunnel-v4 (VPNBOOK only) | ALE_AUTH_CONNECT_V4 | 400 | soft PERMIT | Next-hop interface = reviewed Tailscale LUID |

ARMED has 11 filters; VPNBOOK has 12. ARMED deliberately has no ordinary Tailscale-interface permit, so merely having an exit or accepted subnet route cannot enable application egress under this candidate policy. VPNBOOK permits IPv4 through Tailscale; it has no public IPv6 tunnel exception because the Linux namespace is IPv4-only.

The private sublayer evaluates exceptions before the unconditional denial **within that same sublayer**. The terminating soft permit skips the lower-weight block there, while allowing other providers' restrictions to continue. An ordinary Defender explicit allow in another sublayer does not replace Walnuts' denial. Conversely, Walnuts does not use CLEAR_ACTION_RIGHT to override Windows/enterprise/third-party blocks. Actual arbitration against installed IPsec, callout and hard-permit policies remains a lab acceptance test; no weight is claimed to dominate every possible provider.

UDP destinations/ports can roam, but only the SCM image AND service-SID token can use this reviewed underlay. TCP is limited to 443 for control/DERP. The image hash, protected installation path, live process image, LocalSystem user and service SID membership are checked before install/verify. If Tailscale's actual service token does not carry that SID, installation fails; do not replace it with a broad LocalSystem or CLI exception. Application identity does not cryptographically inspect VPN payloads: the pinned service is trusted to generate its own transport. DNS/control bootstrap under this restricted envelope still needs testing. No dnscache underlay exception exists.

No ordinary DNS/DoH/DoT process has an underlay permit. Native public IPv6 and protocol 41 do not have a general exception. The intended deny coverage for raw traffic and established flows is **not yet proven**, because the chosen layers are ALE authorization layers. ARP is outside these IP layers. IPv6 is not disabled, adapters/drivers are not changed, and only ICMPv6 link-local/multicast is allowed for local maintenance. Other local/Hyper-V management may still be affected by this broad host ALE boundary; preserve an independent hypervisor console and test before using it.

## Engine verification, ownership and recovery

`Engine.Inspect` queries the provider/sublayer and enumerates actual BFE filters within an explicit read transaction (or the enclosing install/remove transaction). It validates versioned metadata, persistence/service binding, provider and sublayer GUIDs, weights, actions, condition operators/types/values, native app blobs, service descriptors and privileged DACLs. It rejects unexpected or orphaned objects referencing the provider/sublayer. Exact native numeric filter IDs and complete expected conditions are returned in JSON. Disabled or modified filters cannot count as a complete set.

Arm/reconcile uses a WFP transaction. It verifies all surviving owned objects before replacement, adds the whole intended set and reads it back before commit, then verifies again. Failure aborts the transaction; it does not remove an older committed boundary. A failed first install can leave no filters, so the helper never labels the machine protected merely because a command was attempted. Missing objects can be recreated from intact, verified provider metadata; mismatched ownership causes refusal. An unchanged complete set causes no replacement.

Removal also runs in a transaction, requires `--confirm-direct` and the explicit deployment ID, verifies surviving objects, deletes only those exact filter GUIDs, then deletes its sublayer/provider. A foreign dependency or mismatch aborts removal. A missing provider plus orphaned sublayer/filter is a blocker, not authorization to delete it. No shared rule/provider flushing occurs. A journal is never sufficient evidence.

The guard is a native SCM-hosted service in the same executable. It checks every two seconds, re-resolves adapter LUIDs and identities, and repairs missing owned objects where safe. Protected `intent.json` records INSTALLING/ACTIVE/REMOVING/REMOVED, manifest and last observed numeric filter IDs using atomic replacement. Complete unexpected provider loss can be repaired from validated INSTALLING/ACTIVE intent; REMOVING/REMOVED suppresses rearming after explicit owner removal. An intact engine manifest remains authoritative over a stale mode request. Verification requires actual engine objects, current identities and matching intent; intent alone is never proof. Stopping/crashing the helper or controller does not intentionally delete persistent filters. Ownership/identity failures retain existing objects and log to bounded protected `guard.log`.

**Persistence limitation:** persistence plus an automatic service is not a verified boot-time or BFE-outage security boundary. No boot-time packet filters or tested handoff are shipped. Watchdog repair is not instantaneous and cannot promise zero leakage after privileged filter deletion. A disappearing/reused adapter LUID also requires actual reauthorization/packet tests. Do not claim complete fail-closed behavior during those intervals.

The concrete next mitigation is a separately reviewed boot-time IP-packet deny policy with a measured handoff to the persistent runtime set. Those packet layers lack ALE app/service identity and may affect forwarded/Hyper-V traffic, so simply copying these exceptions there is invalid. If host/forwarded traffic and boot/BFE coverage cannot be satisfied with supported built-in filters, stop this approach and evaluate an independently enforced dedicated lab gateway or a separately approved callout-based design. This release adds neither a custom driver nor a broad network exception to hide that limitation.

## Helper JSON and exit codes

| Command | Effect |
| --- | --- |
| self-test | Offline native ABI/marshalling/property checks; no engine access |
| inspect / status / verify | Read real engine state and identity; never repair |
| plan | Read fixed lab config and identities, emit exact filters; never install |
| arm --disposable-vm GUID | Transactionally reconcile config mode on the identified installed lab VM |
| remove --disposable-vm GUID --confirm-direct | Explicitly remove verified owned lab objects |
| service | SCM guard entrypoint; not a service installer |

Exit codes: 0 operation/object verification succeeded; 2 deployment/syntax blocked; 3 incomplete protection; 4 identity mismatch; 5 ownership mismatch; 6 unsupported environment; 7 API/internal failure. Error JSON includes the Windows error code when a native call fails. All runtime results keep `ProductionReady=false` and `Protected=false`. `FilterSetVerified` is configuration evidence only. It is never a packet-security verdict.

## Existing disposable VM only — operator sequence

These steps are **lab mutations**, not authorized production instructions. The scripts refuse STREAM and hardware hosts. This session did not find/use an available disposable Windows VM. Creating one on a production host requires separate approval. Use an existing VM with a hypervisor console/checkpoint and a controlled independent receiver; no new tailnet authorization or exit-node advertisement is allowed by these steps.

1. Checkpoint the existing VM. Record its hostname, Tailscale version/identity, physical and Tailscale adapter GUIDs, DHCP DNS, installed service image/hash/signature, firewall/WFP objects and Hyper-V topology. Run the existing firewall Audit. Inspect the Windows service token SID; if missing, stop rather than reconfigure the production service.
2. Copy `client/wfp/lab.example.json` to a reviewed local file. Fill a new deployment GUID, VM hostname, observed adapter GUIDs, SHA256 of the verified SCM executable and mode ARMED_BLOCKED. Empty GUIDs and ***PASTEHERE*** intentionally fail validation.
3. On that VM only, elevated:

```powershell
.\client\wfp\lab\Install-LabWfp.ps1 -DisposableVm -ExpectedHostname WALNUTS-LAB -ReviewedConfiguration .\reviewed-lab.json -WhatIf
.\client\wfp\lab\Install-LabWfp.ps1 -DisposableVm -ExpectedHostname WALNUTS-LAB -ReviewedConfiguration .\reviewed-lab.json -Confirm
& "$env:ProgramFiles\WalnutsWfp\Walnuts.Wfp.exe" plan
```

Installation stages protected files/configuration and creates the automatic BFE-dependent guard service. It does not arm filters. Stop if the plan, SID/path, ACLs or API behavior differs from the review; use console/checkpoint recovery if necessary.

4. Create a lab copy of the existing client config with this VM's real hostname/addresses, the reviewed helper EXE hash and `HelperFiles` companion hashes. This is not a copy of PC-STREAM's identity. Preserve this config in the protected lab directory. Use the actual deployment GUID in `$deployment` below.

```powershell
$deployment=[guid]'***PASTEHERE***'
.\client\walnuts-client.ps1 -Mode BackendPlan -ConfigPath .\reviewed-lab-client.json
.\client\walnuts-client.ps1 -Mode Arm -DisposableVm -DeploymentId $deployment -PlanOnly -ConfigPath .\reviewed-lab-client.json
# Start independent capture and baseline receiver before the next mutation.
.\client\walnuts-client.ps1 -Mode Arm -DisposableVm -DeploymentId $deployment -Confirm -ConfigPath .\reviewed-lab-client.json
.\client\walnuts-client.ps1 -Mode BackendStatus -ConfigPath .\reviewed-lab-client.json
```

Lab Arm captures version-3 DNS/preferences state in the protected ProgramData directory, installs/verifies the native set and clears any exit selection. It does not change Defender profiles/rules. No ordinary tunnel permit exists in ARMED. A failure retains the native set; no DIRECT fallback occurs.

5. Run the matrix below. All rows start UNVERIFIED. Do not select VPNBOOK until ARMED packet coverage is understood and the server/tailnet path is separately approved. For a later isolated VPNBOOK trial, update the protected native config Mode to VPNBOOK, while retaining deployment/identity. The controller requires a fresh artifact `{ "CapturedUtc": "...", "Health": <actual server-health JSON> }`, no older than two minutes, with healthy/guard_present true. This is operator-carried evidence, not cryptographically authenticated server attestation; protect and independently verify it.

```powershell
.\client\walnuts-client.ps1 -Mode VPNBOOK -DisposableVm -DeploymentId $deployment -ServerHealthPath .\fresh-server-health.json -PlanOnly -ConfigPath .\reviewed-lab-client.json
# Only after separately approved server/exit readiness and lab packet checks:
.\client\walnuts-client.ps1 -Mode VPNBOOK -DisposableVm -DeploymentId $deployment -ServerHealthPath .\fresh-server-health.json -Confirm -ConfigPath .\reviewed-lab-client.json
```

The transition requires a verified ARMED engine set. It disables accepted DNS/subnet routes, sets resolvers on the GUID-validated Tailscale interface and selects the reviewed exit with LAN access disabled while application tunnel egress is still blocked. It reads ExitNodeStatus to check the selected exit's address/online state before adding tunnel-v4 transactionally. No Windows Firewall profile change or broad DNS/HTTPS exception occurs. Status remains DEGRADED with separate lab filter evidence until actual acceptance is complete; VPNBOOK_HEALTHY is not emitted from object presence alone.

Lab `-Mode Verify -DisposableVm -DeploymentId $deployment` additionally checks live public IPv4, observed IPv4/IPv6 DNS settings, a unique name under the operator-controlled wildcard `DnsProbeName` client setting, and a forced IPv6 curl probe. These can report VPNBOOK_BLOCKED on failure and never remove filters. They do not prove DNS egress or packet isolation; exit-side capture and the matrix remain mandatory. Failed DNS/tunnel/exit health is not automatic DIRECT authorization.

## Reproducible packet harness and acceptance matrix

On a controlled independent peer VM, start `python client/wfp/lab/receiver.py --bind <receiver-address>` and save stdout; UDP/53 may require privilege. Also capture the receiver's NIC. Configure actual DNS/DoH test endpoints for those tests. Do not use SethLinux as an improvised receiver.

The sender harness refuses production and writes only lab evidence/captures; it never automatically changes firewall rules, adapters, profiles or service state. A sender timeout or successful UDP send never passes a row. The output explicitly records PacketVerdict=UNVERIFIED.

```powershell
$evidence='C:\WalnutsLabEvidence'
.\client\wfp\lab\Invoke-PacketLab.ps1 -DisposableVm -ExpectedHostname WALNUTS-LAB -Stage CaptureStart -EvidenceDirectory $evidence -Confirm
.\client\wfp\lab\Invoke-PacketLab.ps1 -DisposableVm -ExpectedHostname WALNUTS-LAB -Stage Probe -EvidenceDirectory $evidence -SourceIPv4 '***PASTEHERE***' -ReceiverIPv4 '***PASTEHERE***' -ReceiverIPv6 '***PASTEHERE***' -DnsProbeName '***PASTEHERE***' -DohUrl '***PASTEHERE***' -Confirm
.\client\wfp\lab\Invoke-PacketLab.ps1 -DisposableVm -ExpectedHostname WALNUTS-LAB -Stage CaptureStop -EvidenceDirectory $evidence -Confirm
```

Inspect existing pktmon sessions/filters before CaptureStart; never stop another capture. Full NIC packets, component identity and counters are recorded. Confirm packet direction and distinguish ordinary tagged probes from legitimate encrypted daemon traffic. Exported PCAP and receiver logs must agree; no receiver payload alone does not prove no outbound packet. Preserve WFP `inspect` JSON before/after each change, including numeric filter IDs; pktmon counters are not per-filter WFP counters. Use a separately approved WFP diagnostic capture for classification events where available.

| Scenario | Lab procedure/evidence needed | Result in this session |
| --- | --- | --- |
| 1 IPv4 physical bypass | Bound-source tagged TCP probe; physical TX plus receiver capture | Not run |
| 2 Existing Defender allows | Keep representative real/synthetic lab allow rules; same probe must not escape | Not run |
| 3 Tailscale transport | Check control state, direct UDP peer connectivity and encrypted underlay capture | Not run |
| 4 DERP fallback | Use a preconfigured lab relay-only path; confirm TCP443 daemon traffic; do not alter production/firewall to force it | Not run |
| 5 DNS UDP53 | Unique query from bound UDP probe AND Windows DNS Client; both NIC captures | Not run |
| 6 DoH HTTPS | Real operator-controlled RFC8484 URL/query; physical egress must be absent for ordinary process | Not run |
| 7 Native IPv6 | IPv6 peer probe and physical TX capture; distinguish permitted ICMPv6 NDP | Not run |
| 8 Protocol41 | Raw socket probe plus independent protocol41 capture; OS refusal is not WFP proof | Not run |
| 9 Established flows | Run Stream stage in a separate console before Arm, arm while tagged writes continue, compare precise commit time and post-commit packet generation | Not run |
| 10 Tailscale restart | Approved lab-only service restart; compare engine IDs/properties and probes throughout | Not run |
| 11 Helper/controller crash | Close controller and stop only lab guard; persistent set should remain. Probe before repairing | Not run |
| 12 New adapter | Attach an existing test NIC through the disposable VM console; no new public permit should appear | Not run |
| 13 Profile change | Approved lab-only profile transition; capture continued denial | Not run |
| 14 Windows reboot | Independent receiver capture from before shutdown through boot/BFE handoff. Current boot coverage is not implemented/accepted | Not run |
| 15 Ownership removal | Snapshot all providers/filters before/after explicit removal; foreign objects must be identical | Not run |
| 16 DIRECT restoration | Captured preferences/DNS restored, owned objects absent, deliberate direct egress succeeds | Not run |

Also test BFE interruption, adapter LUID reuse, filter deletion/modification, service upgrades/hash changes, partial API failures and Hyper-V forwarded traffic. Reauthorization is documented after policy changes, but that is not packet proof of TCP/raw/forwarded coverage. Reject this layer design if these scenarios leak; do not silently add an unconditional lower-layer allow or a privileged raw bypass. Use checkpoints for destructive lab failures, not automated production “recovery.”

## Explicit owner recovery in the lab

Normally, while Tailscale is available:

```powershell
.\client\walnuts-client.ps1 -Mode DIRECT -DisposableVm -DeploymentId $deployment -ConfirmDirect -PlanOnly -ConfigPath .\reviewed-lab-client.json
.\client\walnuts-client.ps1 -Mode DIRECT -DisposableVm -DeploymentId $deployment -ConfirmDirect -Confirm -ConfigPath .\reviewed-lab-client.json
```

It restores captured DNS and Tailscale accept-dns/accept-routes with the WFP block still installed, then removes only verified native objects. Original Defender profiles are preserved throughout, so this backend does not need to change them back. Legacy version-2 recovery remains separate and refuses rule-name-based deletion.

For an owner at the local VM console when Tailscale or the guard is down, **this explicitly removes protection** and does not depend on either service running:

```powershell
& "$env:ProgramFiles\WalnutsWfp\Walnuts.Wfp.exe" remove --disposable-vm $deployment --confirm-direct
```

BFE must be available for supported WFP removal. The helper requires installed trusted files/configuration and matching deployment identity, but not the guard service registration for removal. Restore DNS from the protected version-3 baseline by adapter GUID and clear exit/DNS preferences when the daemon returns; do not report full DIRECT restoration until that succeeds. An unavailable or changed adapter requires review, never writing a reused index. Corrupt/missing native metadata or ownership mismatch requires checkpoint/manual exact-object review, not a broad flush. Remove the lab guard service/files only after native removal is verified and the owner approves that cleanup; this session does not perform it.

## Remaining deployment blockers

No packet rows are passed. Runtime API installation, service-SID attribution (including DHCP), native ACL canonicalization, DNS bootstrap, existing-flow reauthorization, raw/forwarded/Hyper-V coverage, other-provider arbitration, reboot/BFE handoff and persistent recovery must be established on the disposable VM. The guard's two-second repair loop is not a no-gap guarantee. A supported stable-runtime release build and a signing/distribution review are also needed.

The Linux/tailnet blockers remain: approved actual policy, refreshed device identities/addresses, namespace kill switch, Tailscale marking/SNAT to the veth, namespace NAT and both conntrack return translations, DNS egress, protected-service baselines and server boot/restart behavior. Do not advertise/select the production exit to work around them.

Primary sources: [available WFP conditions by layer](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer), [ALE reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization), [arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration), [persistent/disabled/boot-time flags](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0), [Microsoft SDK definitions](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/fwpmu.h), [pktmon syntax](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start).
