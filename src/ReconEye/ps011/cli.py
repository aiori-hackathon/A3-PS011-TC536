"""CLI entry point for PS-011 scanner."""

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Optional
from ps011.scope import ScopeGuard, ScopeLoadError
from ps011.net import NetClient, ConnectionDenied
from ps011.sinks.audit_log import AuditLogSink
from ps011.models.db import get_db
from ps011.config import load_scope
from ps011.collectors.orchestrator import Orchestrator


async def scan_command(target: str, port: int, scope_path: str) -> int:
    """Execute a scan command against a target.

    Args:
        target: Target hostname or IP.
        port: Target port.
        scope_path: Path to scope.yaml file.

    Returns:
        Exit code: 0 = allowed/connected, 1 = denied, 2 = error.
    """
    try:
        guard = ScopeGuard(scope_path)
    except ScopeLoadError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    client = NetClient(guard)
    sink = AuditLogSink()

    try:
        await client.open(target, port, check_id="CLI_SCAN")
        print(f"ALLOWED: {target}:{port}")
        exit_code = 0
    except ConnectionDenied as e:
        print(f"DENIED: {e.reason}")
        exit_code = 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        exit_code = 2

    # Persist audit log to JSONL file
    if guard.audit_log:
        await sink.write_many(guard.audit_log)

    return exit_code


async def run_command(scope_path: str) -> int:
    """Execute a full scan cycle (run command).
    
    Args:
        scope_path: Path to scope.yaml file.
    
    Returns:
        Exit code: 0 = success, 2 = error.
    """
    try:
        scope_cfg = load_scope(scope_path)
        guard = ScopeGuard(scope_path)
    except ScopeLoadError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    client = NetClient(guard)
    db = get_db()
    db.init_db()

    orchestrator = Orchestrator(guard, client, db, scope_cfg)

    print("Running full scan cycle...")
    try:
        snap = await orchestrator.run_cycle()
        print(f"Snapshot {snap.id}: {snap.status}")
        
        # Count observations
        with db.session() as sess:
            from ps011.models.schema import Observation
            obs_count = sess.query(Observation).filter_by(snapshot_id=snap.id).count()
            print(f"Stored {obs_count} observations")
        
        return 0
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


async def main_async(args: argparse.Namespace) -> int:
    """Async main entry point.

    Args:
        args: Parsed command line arguments.

    Returns:
        Exit code.
    """
    if args.command == "scan":
        scope_path = args.scope or "scope.yaml"
        return await scan_command(args.target, args.port, scope_path)
    elif args.command == "scope-hash":
        try:
            guard = ScopeGuard(args.scope or "scope.yaml")
            print(f"Scope Hash: {guard.get_hash()}")
            return 0
        except ScopeLoadError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
    elif args.command == "run":
        scope_path = args.scope or "scope.yaml"
        return await run_command(scope_path)
    else:
        print("Unknown command", file=sys.stderr)
        return 2


def main(argv: Optional[list[str]] = None) -> None:
    """Main CLI entry point.

    Args:
        argv: Optional argument list (defaults to sys.argv[1:]).
    """
    parser = argparse.ArgumentParser(
        prog="ps011",
        description="PS-011 External Asset Monitoring Tool",
    )
    parser.add_argument(
        "--scope",
        default="scope.yaml",
        help="Path to scope.yaml configuration file",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a target")
    scan_parser.add_argument("--target", required=True, help="Target hostname or IP")
    scan_parser.add_argument("--port", type=int, default=443, help="Target port (default: 443)")
    scan_parser.add_argument("--scope", help="Path to scope.yaml (overrides global --scope)")

    # scope-hash command
    hash_parser = subparsers.add_parser("scope-hash", help="Print scope hash")
    hash_parser.add_argument("--scope", help="Path to scope.yaml (overrides global --scope)")

    # run command
    run_parser = subparsers.add_parser("run", help="Run full scan cycle")
    run_parser.add_argument("--scope", help="Path to scope.yaml (overrides global --scope)")

    args = parser.parse_args(argv)
    exit_code = asyncio.run(main_async(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()