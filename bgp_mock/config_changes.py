"""Baseline and modified router configs for a config-change anomaly."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from bgp_mock.io_util import load_json, write_gz
from bgp_mock.timeutil import format_tag

CONFIG_DIR = Path("netdb-data/config/updates")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def load_config_changes(path: Path) -> list[dict]:
    data = load_json(Path(path))
    if isinstance(data, dict):
        records = data.get("records")
    else:
        records = data
    if not isinstance(records, list):
        raise ValueError(f"{path}: config input must be a list or {{\"records\": [...]}}")
    return records


def _safe(name: str) -> str:
    cleaned = _SAFE_NAME.sub("_", name.strip())
    if not cleaned:
        raise ValueError("router_name is empty")
    return cleaned


def _need_text(record: dict, key: str, index: int, required: bool) -> str:
    value = record.get(key)
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"config record {index}: {key} must be a string")
    if required and not value.strip():
        raise ValueError(f"config record {index}: {key} is required")
    if value and not value.endswith("\n"):
        value += "\n"
    return value


def write_config_changes(
    records: list[dict],
    base_directory: Path,
    now: datetime,
    force: bool = False,
) -> list[dict]:
    """Write baseline.cfg, modified.cfg, and a pipe index that points at both."""
    if not records:
        print("[config] no records, skipped", flush=True)
        return []
    tag = format_tag(now)
    date_text = now.strftime("%Y%m%d")
    index_rows = [
        "router_name|network|date|update_type|baseline_path|modified_path"
    ]
    written_files: list[dict] = []
    seen: dict[str, int] = {}
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"config record {index}: expected an object")
        router = str(record.get("router_name") or "").strip()
        if not router:
            raise ValueError(f"config record {index}: router_name is required")
        update_type = str(record.get("update_type") or "M").strip().upper()
        if update_type not in {"A", "D", "M"}:
            raise ValueError(
                f"config record {index}: update_type must be A, D, or M"
            )
        network = str(record.get("network") or "")
        if "|" in router or "|" in network:
            raise ValueError(f"config record {index}: router_name and network cannot contain '|'")
        baseline = _need_text(record, "baseline_config", index, required=update_type != "A")
        modified = _need_text(record, "modified_config", index, required=update_type != "D")
        seen[router] = seen.get(router, 0) + 1
        suffix = "" if seen[router] == 1 else f"_{seen[router]}"
        folder = Path(base_directory) / CONFIG_DIR / tag
        stem = _safe(router) + suffix
        baseline_path = folder / f"{stem}_baseline.cfg"
        modified_path = folder / f"{stem}_modified.cfg"
        for path, body in ((baseline_path, baseline), (modified_path, modified)):
            if path.exists() and not force:
                raise FileExistsError(
                    f"refusing to overwrite {path}. Pass --force or set \"force\": true."
                )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        rel_base = baseline_path.relative_to(base_directory).as_posix()
        rel_mod = modified_path.relative_to(base_directory).as_posix()
        index_rows.append(
            "|".join([router, network, date_text, update_type, rel_base, rel_mod])
        )
        written_files.append(
            {
                "router_name": router,
                "update_type": update_type,
                "baseline_path": str(baseline_path),
                "modified_path": str(modified_path),
            }
        )
    index_path = Path(base_directory) / CONFIG_DIR / f"Config_Changes_{tag}.txt.gz"
    info = write_gz(index_path, "\n".join(index_rows) + "\n", force=force)
    info.update(
        {
            "kind": "config_changes",
            "tag": tag,
            "records": len(records),
            "files": written_files,
        }
    )
    print(f"[config] records={len(records)} -> {index_path}", flush=True)
    return [info]
