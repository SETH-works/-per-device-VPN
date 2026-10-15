"""Offline tailnet policy review helpers; never apply policy changes."""
from __future__ import annotations

from typing import Any

PILOT_TAG = "tag:pc-stream-vpnbook-pilot"

def audit_exit_node_access(policy: dict[str, Any], pilot_ipv4: str) -> tuple[str, ...]:
    """Report additive grants that can authorize more than the intended pilot.

    This is a conservative structural audit. Tailscale policy semantics still
    require the official policy-test command and admin review.
    """
    issues: list[str] = []
    tag_owners = policy.get("tagOwners", {})
    if tag_owners.get(PILOT_TAG) != ["autogroup:admin"]:
        issues.append("pilot_tag_must_be_owned_only_by_autogroup_admin")
    grants = policy.get("grants", [])
    broad_destinations = {"*", "0.0.0.0/0", "::/0", "*:*", "0.0.0.0/0:*", "::/0:*"}
    for index, grant in enumerate(grants):
        destinations = set(grant.get("dst", []))
        if not ("autogroup:internet" in destinations or destinations & broad_destinations):
            continue
        if grant.get("src") != [PILOT_TAG]:
            issues.append(f"grant_{index}_also_authorizes_nonpilot_exit_node_use")
    # Legacy ACL policy can also grant exit-node use. Do not assume a new grant narrows it.
    for index, acl in enumerate(policy.get("acls", [])):
        destinations = set(acl.get("dst", []))
        broad_acl = {"*:*", "0.0.0.0/0:*", "::/0:*"}
        if ("autogroup:internet:*" in destinations or destinations & broad_acl) and pilot_ipv4 not in acl.get("src", []):
            issues.append(f"acl_{index}_may_authorize_broader_exit_node_use")
    if not any(PILOT_TAG in grant.get("src", []) and "autogroup:internet" in grant.get("dst", [])
               for grant in grants):
        issues.append("pilot_exit_node_grant_missing")
    return tuple(issues)
