"""Run the pieces named by a scenario file."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from bgp_mock.cmdb import load_cmdb, write_cmdb
from bgp_mock.config_changes import load_config_changes, write_config_changes
from bgp_mock.io_util import load_json, resolve_path, write_json
from bgp_mock.rib import load_rt_allowlist
from bgp_mock.snapshot import filter_snapshot
from bgp_mock.timeutil import as_utc, format_tag, parse_now
from bgp_mock.updates import load_updates, write_updates


def _section(scenario: dict, key: str) -> dict | None:
    value = scenario.get(key)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"scenario.{key} must be an object")
    return value


def run_scenario(
    scenario_path: Path,
    base_directory: Path | None = None,
    now: datetime | None = None,
    force: bool | None = None,
    minutes_ago: int | None = None,
    snapshot_override: Path | None = None,
) -> dict:
    """Read one scenario and write the sections that are present."""
    scenario_path = Path(scenario_path)
    scenario = load_json(scenario_path)
    if not isinstance(scenario, dict):
        raise ValueError(f"{scenario_path}: scenario must be a JSON object")

    here = scenario_path.parent
    if base_directory is None:
        raw_base = scenario.get("base_directory")
        if not raw_base:
            raise ValueError("base_directory is required (scenario or --base-directory)")
        base_directory = resolve_path(Path.cwd(), str(raw_base))
    base_directory = Path(base_directory)
    base_directory.mkdir(parents=True, exist_ok=True)

    if now is None:
        now = parse_now(scenario.get("now"))
    now = as_utc(now)
    if force is None:
        force = bool(scenario.get("force", False))
    if minutes_ago is None:
        minutes_ago = int(scenario.get("snapshot_minutes_ago", 45))

    outputs: list[dict] = []
    generated_snapshot: str | None = None

    snapshot_cfg = _section(scenario, "snapshot")
    if snapshot_cfg is not None:
        source = resolve_path(here, str(snapshot_cfg["source"]))
        allow_path = resolve_path(here, str(snapshot_cfg["rt_allowlist"]))
        allow = load_rt_allowlist(allow_path)
        written = filter_snapshot(
            source=source,
            allow=allow,
            base_directory=base_directory,
            now=now,
            minutes_ago=minutes_ago,
            keep_idl=bool(snapshot_cfg.get("keep_idl", True)),
            force=force,
        )
        outputs.append(written)
        generated_snapshot = written["path"]

    cmdb_cfg = _section(scenario, "cmdb")
    if cmdb_cfg is not None:
        changes = load_cmdb(resolve_path(here, str(cmdb_cfg["input"])))
        outputs.extend(write_cmdb(changes, base_directory, now, force=force))

    config_cfg = _section(scenario, "config_changes")
    if config_cfg is not None:
        records = load_config_changes(resolve_path(here, str(config_cfg["input"])))
        outputs.extend(write_config_changes(records, base_directory, now, force=force))

    updates_cfg = _section(scenario, "bgp_updates")
    if updates_cfg is not None:
        spec = load_updates(resolve_path(here, str(updates_cfg["input"])))
        snapshot_path = _resolve_update_snapshot(
            updates_cfg, spec, here, generated_snapshot, snapshot_override
        )
        outputs.extend(
            write_updates(spec, snapshot_path, base_directory, now, force=force)
        )

    manifest = {
        "scenario": str(scenario_path),
        "base_directory": str(base_directory),
        "now": now.isoformat(),
        "tag": format_tag(now),
        "snapshot_minutes_ago": minutes_ago,
        "outputs": outputs,
    }
    manifest_path = base_directory / "mock-generator" / "latest.json"
    write_json(manifest_path, manifest)
    print(f"[done] manifest -> {manifest_path}", flush=True)
    return manifest


def _resolve_update_snapshot(
    updates_cfg: dict,
    spec: dict,
    here: Path,
    generated_snapshot: str | None,
    override: Path | None,
) -> Path | None:
    if override is not None:
        return Path(override)
    raw = updates_cfg.get("snapshot", spec.get("snapshot"))
    if raw is None:
        return Path(generated_snapshot) if generated_snapshot else None
    if str(raw) == "generated":
        if not generated_snapshot:
            raise ValueError(
                "bgp_updates.snapshot is \"generated\" but the scenario did not write a snapshot"
            )
        return Path(generated_snapshot)
    return resolve_path(here, str(raw))
