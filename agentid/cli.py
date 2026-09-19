"""``agentid`` command line: initialise, seed, inspect and serve."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .config import get_settings
from .database.engine import create_all, get_engine, session_scope
from .database.seed import seed as seed_database


def _cmd_init(_args: argparse.Namespace) -> int:
    create_all(get_engine())
    print(f"schema created in {get_settings().database_url}")
    return 0


def _cmd_seed(args: argparse.Namespace) -> int:
    create_all(get_engine())
    endpoints = json.loads(args.endpoints) if args.endpoints else None
    with session_scope() as db:
        result = seed_database(db, policy_file=args.policy, endpoints=endpoints)
        print(result.summary())
        for name, key in result.api_keys.items():
            print(f"api key for {name}: {key}")
    return 0


def _cmd_policy(args: argparse.Namespace) -> int:
    from .authorization.policies import PolicyBundle

    with session_scope() as db:
        roles = PolicyBundle.load(args.file).apply(db)
        print(f"applied {len(roles)} roles: {', '.join(r.name for r in roles)}")
    return 0


def _cmd_roles(_args: argparse.Namespace) -> int:
    from .authorization.rbac import list_roles

    with session_scope() as db:
        for role in list_roles(db):
            print(f"{role.name}")
            for name in sorted(role.allowed()):
                print(f"  allow {name}")
            for name in sorted(role.denied()):
                print(f"  deny  {name}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    target = {
        "gateway": "agentid.gateway.main:app",
        "github": "agentid.servers.github.server:app",
        "postgres": "agentid.servers.postgres.server:app",
        "kubernetes": "agentid.servers.kubernetes.server:app",
    }[args.component]
    uvicorn.run(target, host=args.host, port=args.port, reload=args.reload)
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    from scripts.demo import run_demo

    return run_demo(json_output=args.json)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentid", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the database schema").set_defaults(func=_cmd_init)

    seed_parser = sub.add_parser("seed", help="load the demo identities, policies and registry")
    seed_parser.add_argument("--policy", help="policy bundle to apply", default=None)
    seed_parser.add_argument(
        "--endpoints", help="JSON map of server name -> endpoint", default=None
    )
    seed_parser.set_defaults(func=_cmd_seed)

    policy_parser = sub.add_parser("policy", help="apply a policy bundle")
    policy_parser.add_argument("file")
    policy_parser.set_defaults(func=_cmd_policy)

    sub.add_parser("roles", help="print the effective roles").set_defaults(func=_cmd_roles)

    serve_parser = sub.add_parser("serve", help="run a component")
    serve_parser.add_argument(
        "component",
        choices=["gateway", "github", "postgres", "kubernetes"],
        nargs="?",
        default="gateway",
    )
    serve_parser.add_argument("--host", default="0.0.0.0")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--reload", action="store_true")
    serve_parser.set_defaults(func=_cmd_serve)

    demo_parser = sub.add_parser("demo", help="run the end-to-end security demo")
    demo_parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    demo_parser.set_defaults(func=_cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler: Any = args.func
    return int(handler(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
