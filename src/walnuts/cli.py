"""Small local validation command; no privileged or network operations."""

from __future__ import annotations

import argparse
import sys

from .plan import PlanError, load_plan


def main() -> int:
    parser = argparse.ArgumentParser(prog="walnuts")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate a declarative plan without applying it")
    validate.add_argument("plan")
    args = parser.parse_args()
    if args.command == "validate":
        try:
            plan = load_plan(args.plan)
        except (OSError, PlanError) as exc:
            print(f"Invalid plan: {exc}", file=sys.stderr)
            return 2
        print(f"Plan valid: {len(plan.devices)} device(s), {len(plan.exits)} exit(s). No network changes applied.")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

