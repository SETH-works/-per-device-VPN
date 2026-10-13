# Project Walnuts

Project Walnuts is a provider-neutral network control platform for SethLinux. It is intended to assign Direct or VPN policies to verified devices while preserving existing services and DNS filtering.

## Current implementation

This repository currently contains a non-privileged control-plane foundation:

- A strict, versioned TOML policy-plan loader.
- Provider-neutral device and exit types.
- Decision-only policy evaluation. It does not apply routes, firewall rules, DNS, or NAT.
- VPN exit selection gates requiring recent tunnel, public IPv4 egress, DNS, IPv6, and credential evidence.
- A local `walnuts validate` command that validates plans without applying them.
- Unit tests for fail-closed behavior, explicit selected-VPN fallback, unverified identities, and health evidence.

No live host audit has been completed. No endpoint is verified, no device selector is configured, and no network policy is active. The sample plan intentionally leaves all devices unenrolled and VPN exits unverified.

## Local development

Requires Python 3.11 or later. The core has no runtime third-party dependencies.

From the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python -m walnuts.cli validate config/plan.example.toml
```

On Linux/macOS, use `PYTHONPATH=src python3 -m unittest discover -s tests -v` and `PYTHONPATH=src python3 -m walnuts.cli validate config/plan.example.toml`.

## SSH discovery prerequisite

The managed Gateway entry is staged but has no endpoint yet. Before assigning it, verify the SethLinux SSH host key fingerprint from its local console:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Provide the SHA256 fingerprint to pin the host identity during endpoint registration. This fingerprint is public and is not a credential. Do not paste a private key or credentials into chat. Use the least-privileged Gateway access first; request narrowly scoped sudo only when a specific inventory command requires it. Keep SSH and management services off the public internet.

## Safety boundary

Phase 0 remains read-only. Do not change the host default route, router, firewall, DNS, VPN services, packages, or production configuration until the inventory and baseline are complete and the exact change has explicit approval. Routing and privileged integration will be implemented only after the live boundaries are understood.

Keep environment-specific inventory in a private local note, excluded from the public repository. Redact keys, credentials, tokens, and unnecessary network identifiers.
