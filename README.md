# Project Walnuts

Project Walnuts is a provider-neutral network control platform for SethLinux. It is intended to assign Direct or VPN policies to verified devices while preserving existing services and DNS filtering.

## Current implementation

This repository currently contains a non-privileged control-plane foundation:

- A strict, versioned TOML policy-plan loader.
- Provider-neutral device and exit types.
- Decision-only policy evaluation. It does not apply routes, firewall rules, DNS, or NAT.
- Explicit, timestamped VPN-exit inventory and manual selection decisions.
- Declarative DNS/IPv6 protection checks, structured audit records, and recovery-state assessment.
- VPN exit selection gates requiring recent tunnel, public IPv4 egress, DNS, IPv6, and credential evidence.
- A single-device Tailscale-to-VPNBook pilot planner with strict prerequisites, health checks, a dry-run-only CLI, and scoped rollback steps. The planner does not execute host or tailnet changes.
- A local `walnuts validate` command that validates plans without applying them.
- Unit tests for fail-closed behavior, explicit selected-VPN fallback, unverified identities, and health evidence.

Gateway SSH access to SethLinux has been verified for unprivileged read-only discovery. Gateway sudo diagnostics found that `/usr/bin/sudo` resolves to the Ubuntu `sudo-rs` provider under `/usr/lib/cargo/bin`, which Gateway currently rejects as outside a trusted executable path; no sudo or system file was changed. Read-only inventory confirmed the host IPv4 default route, Tailscale policy routing, and `vpnbook` namespace existence. Namespace internals, effective firewall rules, Docker workload inventory, router details, and device identities remain unverified. The pilot records `147.135.15.16` and `198.29.53.14` as user-supplied expected egress values; tunnel-path, DNS, and IPv6 health checks remain required before selection. The example policy leaves all devices unenrolled and VPN exits unverified. See `docs/phase1-tailscale-vpnbook-pilot.md`.

## Local development

Requires Python 3.11 or later. The core has no runtime third-party dependencies.

From the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python -m walnuts.cli validate config/plan.example.toml
python -m walnuts.cli pilot-plan config/pilot.example.toml
```

`pilot-plan` is a planning-only command. The example intentionally reports blockers. It never applies network changes.

On Linux/macOS, use `PYTHONPATH=src python3 -m unittest discover -s tests -v` and `PYTHONPATH=src python3 -m walnuts.cli validate config/plan.example.toml`.

## Current discovery boundary

Use the existing private Gateway connection. Continue read-only inventory through the existing access path. Gateway sudo compatibility with the installed sudo-rs trusted path remains unresolved; do not replace sudo, alter alternatives, or modify privileged files as a workaround. Keep the pilot offline until the VPN, DNS, firewall, Docker, and tailnet policy boundaries are understood.

## Safety boundary

Phase 0 remains read-only. Do not change the host default route, router, firewall, DNS, VPN services, packages, or production configuration until the inventory and baseline are complete and the exact change has explicit approval. Routing and privileged integration will be implemented only after the live boundaries are understood.

Keep environment-specific inventory in a private local note, excluded from the public repository. Redact keys, credentials, tokens, and unnecessary network identifiers.
