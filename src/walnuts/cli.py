"""Small local validation command; no privileged or network operations."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib

from .plan import PlanError, load_plan
from .pilot import PilotSpec, load_pilot_plan
from .server_adapter import AdapterError, LinuxPilotAdapter


def main() -> int:
    parser = argparse.ArgumentParser(prog="walnuts")
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate a declarative plan without applying it")
    validate.add_argument("plan")
    pilot_plan = sub.add_parser("pilot-plan", help="render a non-executable, fail-closed Tailscale pilot plan")
    pilot_plan.add_argument("plan")
    for name, help_text in (("server-preflight", "read-only live server preflight"),
                            ("server-dry-run", "show exact staged server changes without applying"),
                            ("server-install", "explicitly install the pilot adapter"),
                            ("server-guard", "install only persistent fail-closed guards"),
                            ("server-status", "inspect recorded adapter state"),
                            ("server-health", "run read-only operational health checks"),
                            ("server-remove", "remove only owned pilot objects after client DIRECT")):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("config")
        if name == "server-remove":
            command.add_argument("--confirm-client-direct", action="store_true")
        if name == "server-install":
            command.add_argument("--apply", action="store_true", help="required explicit mutation switch")
    args = parser.parse_args()
    if args.command == "validate":
        try:
            plan = load_plan(args.plan)
        except (OSError, PlanError) as exc:
            print(f"Invalid plan: {exc}", file=sys.stderr)
            return 2
        print(f"Plan valid: {len(plan.devices)} device(s), {len(plan.exits)} exit(s). No network changes applied.")
        return 0
    if args.command.startswith("server-"):
        try:
            with open(args.config, "rb") as stream:
                config = tomllib.load(stream)
            spec = PilotSpec(**config["pilot"])
            adapter = LinuxPilotAdapter(spec, deployment_evidence=config.get("evidence", {}))
            if args.command == "server-preflight":
                result = adapter.preflight()
                print(json.dumps({"ready": not result.blockers, "blockers": result.blockers,
                                  "observed": result.observed}, indent=2))
                return 0 if not result.blockers else 2
            if args.command == "server-dry-run":
                result = adapter.preflight()
                print(json.dumps({"ready": not result.blockers,
                                  "blockers": result.blockers,
                                  "commands": [list(c) for c in adapter.commands()],
                                  "host_nft": adapter._nft_host("WALNUTS_INSTANCE"),
                                  "namespace_nft": adapter._nft_namespace("WALNUTS_INSTANCE")}, indent=2))
                return 0 if not result.blockers else 2
            if args.command == "server-install":
                if not args.apply:
                    print("No changes. Re-run with --apply only after approving the reviewed deployment plan.", file=sys.stderr)
                    return 2
                result, commands = adapter.install()
                print(json.dumps({"installed": True, "commands": commands,
                                  "preflight": result.observed}, indent=2))
                return 0
            if args.command == "server-guard":
                print(json.dumps(adapter.ensure_guard(), indent=2))
                return 0
            if args.command == "server-status":
                print(json.dumps(adapter.status(), indent=2))
                return 0
            if args.command == "server-health":
                result = adapter.health()
                print(json.dumps(result, indent=2))
                return 0 if result["healthy"] else 2
            if args.command == "server-remove":
                adapter.remove(confirm_client_direct=args.confirm_client_direct)
                print("Walnuts-owned server objects removed.")
                return 0
        except (OSError, KeyError, TypeError, ValueError, AdapterError) as exc:
            print(f"Server operation blocked: {exc}", file=sys.stderr)
            return 2
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

