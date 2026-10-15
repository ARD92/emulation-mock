"""Command line for the BGP mock generator."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from bgp_mock.cmdb import TABLES, load_cmdb, write_cmdb
from bgp_mock.config_changes import load_config_changes, write_config_changes
from bgp_mock.rib import load_rt_allowlist
from bgp_mock.scenario import run_scenario
from bgp_mock.snapshot import filter_snapshot
from bgp_mock.timeutil import parse_now
from bgp_mock.updates import load_updates, write_updates


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-directory", required=True, help="Mailbox root.")
    parser.add_argument("--now", help="ISO-8601 UTC timestamp. Default: current UTC time.")
    parser.add_argument("--force", action="store_true", help="Replace an existing output file.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bgp_mock",
        description="Generate filtered BGP snapshots, CMDB updates, and BGP update files.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run every section listed in a scenario file.")
    run.add_argument("scenario", help="Path to the scenario JSON file.")
    run.add_argument("--base-directory", help="Overrides scenario base_directory.")
    run.add_argument("--now", help="ISO-8601 UTC timestamp. Default: scenario now, else current UTC.")
    run.add_argument("--force", action="store_true")
    run.add_argument(
        "--minutes-ago",
        type=int,
        help="Snapshot age in minutes. Default 45, inside the 30 to 60 minute window.",
    )
    run.add_argument(
        "--snapshot",
        help="Dump used by BGP update actions. Overrides the scenario.",
    )

    snap = sub.add_parser("snapshot", help="Filter a dump by an RT allowlist file.")
    _add_common(snap)
    snap.add_argument("--source", required=True, help="Input dump (.txt or .txt.gz).")
    snap.add_argument("--rt-allowlist", required=True, help="RT list file.")
    snap.add_argument("--minutes-ago", type=int, default=45)
    snap.add_argument(
        "--no-idl",
        action="store_true",
        help="Drop SAFI 4 rows. Default keeps IDL rows that pass the engine2 session gates.",
    )

    cmdb = sub.add_parser("cmdb", help="Write CMDB pipe files from an input file.")
    _add_common(cmdb)
    cmdb.add_argument("--input", required=True)

    updates = sub.add_parser("updates", help="Write BGP update files from an action file.")
    _add_common(updates)
    updates.add_argument("--input", required=True)
    updates.add_argument("--snapshot", help="Dump used by select blocks.")

    config = sub.add_parser("config", help="Write baseline and modified configs.")
    _add_common(config)
    config.add_argument("--input", required=True)

    sub.add_parser("datasets", help="List CMDB datasets and their output paths.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except (ValueError, FileNotFoundError, FileExistsError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "datasets":
        for name, spec in TABLES.items():
            print(f"{name}\t{spec.directory}/{spec.filename}")
        return 0

    now = parse_now(getattr(args, "now", None))
    if args.command == "run":
        manifest = run_scenario(
            scenario_path=Path(args.scenario),
            base_directory=Path(args.base_directory) if args.base_directory else None,
            now=parse_now(args.now) if args.now else None,
            force=True if args.force else None,
            minutes_ago=args.minutes_ago,
            snapshot_override=Path(args.snapshot) if args.snapshot else None,
        )
        print(json.dumps({"outputs": len(manifest["outputs"]), "tag": manifest["tag"]}))
        return 0

    base = Path(args.base_directory)
    force = bool(args.force)
    if args.command == "snapshot":
        written = filter_snapshot(
            source=Path(args.source),
            allow=load_rt_allowlist(Path(args.rt_allowlist)),
            base_directory=base,
            now=now,
            minutes_ago=args.minutes_ago,
            keep_idl=not args.no_idl,
            force=force,
        )
    elif args.command == "cmdb":
        written = write_cmdb(load_cmdb(Path(args.input)), base, now, force=force)
    elif args.command == "updates":
        snapshot = Path(args.snapshot) if args.snapshot else None
        written = write_updates(load_updates(Path(args.input)), snapshot, base, now, force=force)
    elif args.command == "config":
        written = write_config_changes(
            load_config_changes(Path(args.input)), base, now, force=force
        )
    else:
        raise ValueError(f"unknown command {args.command}")
    print(json.dumps(written, indent=2))
    return 0
