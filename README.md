# Project Walnuts

SethLinux network control and selective VPN project.

## Goal

Develop a secure, understandable way to choose Direct or VPN egress independently for enrolled devices, preserve Pi-hole filtering where feasible, and keep household network services stable.

## Current phase

**Phase 0: discovery, architecture, and risk assessment.** No implementation or network changes are authorized until the current system is inspected, a proposed design is reviewed, and explicit approval is given.

## Working rules

- Treat the host's primary routing, LAN/SSH, DNS filtering, existing VPN, containers, and published services as protected until mapped.
- Do not change router, firewall, routing, DNS, packages, services, or device policies during discovery.
- Do not assign policies to an unknown device or MAC address.
- Do not expose credentials, keys, or private network identifiers in public project material.
- Label findings as verified, inferred, or requiring investigation.

The detailed environment-specific discovery review is maintained separately until it can be safely redacted for this public repository.
