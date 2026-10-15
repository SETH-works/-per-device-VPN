"""Small local validation command; no privileged or network operations."""

from __future__ import annotations

import argparse
import sys

from .plan import PlanError, load_plan
from .pilot import load_pilot_plan


def main() -> int:
    parser = argparse.ArgumentParser(prog="walnuts")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate a declarative plan without applying it")
    validate.add_argument("plan")
    pilot_plan = sub.add_parser("pilot-plan", help="render a non-executable, fail-closed Tailscale pilot plan")
    pilot_plan.add_argument("plan")
    args = parser.parse_args()
    if args.command == "validate":
        try:
            plan = load_plan(args.plan)
        except (OSError, PlanError) as exc:
            print(f"Invalid plan: {exc}", file=sys.stderr)
            return 2
        print(f"Plan valid: {len(plan.devices)} device(s), {len(plan.exits)} exit(s). No network changes applied.")
        return 0
    if args.command == "pilot-plan":
        try:
            plan = load_pilot_plan(args.plan)
        except (OSError, ValueError) as exc:
            print(f"Invalid pilot plan: {exc}", file=sys.stderr)
            return 2
        if not plan.ready:
            print("PILOT PLAN BLOCKED — dry-run only; no network changes applied.")
            for blocker in plan.blockers:
                print(f"- {blocker}")
            return 2
        print("PILOT PLAN READY FOR REVIEW — dry-run only; this command never applies changes.")
        for heading, actions in (("Configure", plan.configure_actions),
                                 ("Rollback", plan.rollback_actions),
                                 ("Acceptance checks", plan.acceptance_checks)):
            print(f"\n{heading}:")
            for index, action in enumerate(actions, 1):
                print(f"{index}. {action}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

