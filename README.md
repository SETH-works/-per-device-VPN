# Project Walnuts

Project Walnuts is a provider-neutral network control project for SethLinux. Phase 1 is a reversible, one-device PC-STREAM pilot that can direct traffic through SethLinux's existing isolated VPNBook WireGuard namespace.

## Current implementation

- Strict TOML policy planning, device/exit models, decision-only policy evaluation, health evidence, audit records, and recovery-state assessment.
- Single-device Tailscale-to-VPNBook dry-run planner.
- Linux server adapter with read-only preflight/status/health, complete dry-run output, staged installation, boot-time fail-closed nftables guard, per-object ownership journal, re-entry after reboot, and exact-object teardown.
- PC-STREAM PowerShell controller with structured effective-firewall audit and gated legacy DIRECT recovery. Arm, VPNBOOK and Verify are disabled before any change because the previous Windows Firewall design cannot guarantee underlay separation. A native WFP helper is proposed for review; no backend, driver or service is shipped.
- Offline structural tailnet policy audit and proposed admin-owned tag/grant fragment.
- Unit tests for planner and policy behavior plus mocked Linux-adapter and client-controller safety checks.

No production network, DNS, firewall, routing, Tailscale advertisement, tailnet policy, or Windows client settings have been changed. Deployment remains blocked pending privileged live snapshots, current endpoint refresh, proof of the two-stage NAT path, tailnet policy review, Windows Firewall validation, protected-service baselines, boot rehearsal, and explicit approval. See [the Phase 1 operator runbook](docs/phase1-operator-runbook.md).

## Local development

Requires Python 3.11 or later. The Python core has no runtime third-party dependencies.

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
python -m walnuts.cli validate config/plan.example.toml
python -m walnuts.cli pilot-plan config/pilot.example.toml
python -m walnuts.cli server-dry-run config/pilot.example.toml
```

`pilot-plan` and `server-dry-run` never apply changes. Linux `server-guard`, `server-install --apply`, and `server-remove --confirm-client-direct` are mutating commands and require root. The example config intentionally remains blocked until live observations and reviewed evidence are filled in. The Windows controller's `-PlanOnly` and `Status` modes are read-only; changing mode requires administrator rights and explicit invocation.

Run the behavioral Windows audit tests with `Invoke-Pester client/tests/walnuts-firewall.Tests.ps1`. The Python suite also executes blocked controller modes in child PowerShell processes with side-effect traps. These are offline behavior tests, not live WFP enforcement tests.

The sample values in the config are historical observations; refresh them before any deployment review. Do not store WireGuard private keys, credentials, or tokens in this repository.
