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
- A local `walnuts validate` command that validates plans without applying them.
- Unit tests for fail-closed behavior, explicit selected-VPN fallback, unverified identities, and health evidence.

Gateway SSH access to SethLinux has been verified. Unprivileged inventory confirmed the host interfaces, default IPv4 route, DNS resolver state, Tailscale link, and existence of the `vpnbook` namespace. Privileged discovery remains pending because Gateway sudo access has not been enabled. No endpoint is verified, no device selector is configured, and no network policy is active. The sample plan intentionally leaves all devices unenrolled and VPN exits unverified.

## Local development

Requires Python 3.11 or later. The core has no runtime third-party dependencies.

From the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python -m walnuts.cli validate config/plan.example.toml
```

On Linux/macOS, use `PYTHONPATH=src python3 -m unittest discover -s tests -v` and `PYTHONPATH=src python3 -m walnuts.cli validate config/plan.example.toml`.

## Current discovery boundary

Use the existing private Gateway connection. Privileged inventory requires temporary sudo authorization through Gateway; never send passwords or credentials through chat. Keep all Phase 1 engine work offline until the live VPN, DNS, firewall, Docker, and router boundaries are understood.

## Safety boundary

Phase 0 remains read-only. Do not change the host default route, router, firewall, DNS, VPN services, packages, or production configuration until the inventory and baseline are complete and the exact change has explicit approval. Routing and privileged integration will be implemented only after the live boundaries are understood.

Keep environment-specific inventory in a private local note, excluded from the public repository. Redact keys, credentials, tokens, and unnecessary network identifiers.
