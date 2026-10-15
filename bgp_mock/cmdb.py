"""CMDB pipe files. Add a dataset by appending one TableSpec to TABLES."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from bgp_mock.io_util import load_json, write_gz
from bgp_mock.timeutil import format_tag

UPDATE_TYPES = frozenset({"A", "D", "M"})


@dataclass(frozen=True)
class TableSpec:
    """One mailbox file.

    `header` is the exact first line. `date_fields` maps a column to strftime.
    `optional` columns may be omitted and are written as empty.
    """

    name: str
    directory: str
    filename: str
    header: tuple[str, ...]
    date_fields: dict[str, str]
    optional: frozenset[str] = frozenset()


TABLES: dict[str, TableSpec] = {
    "bgp_cmdb": TableSpec(
        name="bgp_cmdb",
        directory="netdb-data/bgp/updates",
        filename="Loopback_to_RouterName_{tag}.txt.gz",
        header=(
            "interface_ip",
            "router_name",
            "router_date",
            "network",
            "loopback",
            "interface_ip2",
            "primary_ind",
            "update_type",
        ),
        date_fields={"router_date": "%Y%m%d"},
        optional=frozenset({"interface_ip2"}),
    ),
    "session_limit_cmdb": TableSpec(
        name="session_limit_cmdb",
        directory="netdb-data/prefix_limits/updates",
        filename="Session_Limits_{tag}.txt.gz",
        header=(
            "network",
            "src_name",
            "target_address",
            "ip_type",
            "direction",
            "max_prefixes",
            "max_prefix_threshold_pct",
            "thresh_action",
            "date",
            "update_type",
        ),
        date_fields={"date": "%Y%m%d"},
    ),
    "vrf_limits": TableSpec(
        name="vrf_limits",
        directory="netdb-data/prefix_limits/updates",
        filename="VRF_Limits_{tag}.txt.gz",
        header=(
            "network",
            "router_name",
            "vrf_name",
            "description",
            "route_distinguisher",
            "ip_type",
            "max_prefixes",
            "max_prefix_threshold_pct",
            "thresh_action",
            "date",
            "update_type",
        ),
        date_fields={"date": "%Y%m%d"},
        optional=frozenset({"description"}),
    ),
    "rr_plane_cmdb": TableSpec(
        name="rr_plane_cmdb",
        directory="netdb-data/prefix_limits/updates",
        filename="RR_Plane_Cluster_{tag}.txt.gz",
        header=(
            "network",
            "router_name",
            "plane",
            "cluster_id",
            "cluster_name",
            "file_date",
            "update_type",
        ),
        date_fields={"file_date": "%Y-%m-%d"},
    ),
    "rt_limits": TableSpec(
        name="rt_limits",
        directory="netdb-data/prefix_limits/updates",
        filename="RT_Limits_cmdb_{tag}.txt.gz",
        header=(
            "NETWORK",
            "ROUTER_NAME",
            "VRF_NAME",
            "DIRECTION",
            "RT",
            "MAX_PREFIXES",
            "MAX_PREFIX_THRESHOLD_PCT",
            "THRESH_ACTION",
            "DATE",
            "UPDATE_TYPE",
        ),
        date_fields={"DATE": "%Y%m%d"},
    ),
}


def _lookup(record: dict, column: str):
    if column in record:
        return record[column]
    lowered = column.lower()
    for key, value in record.items():
        if str(key).lower() == lowered:
            return value
    raise KeyError(column)


def _cell(record: dict, column: str, spec: TableSpec, when: datetime, index: int) -> str:
    try:
        value = _lookup(record, column)
    except KeyError:
        if column in spec.date_fields:
            value = when.strftime(spec.date_fields[column])
        elif column in spec.optional:
            value = ""
        else:
            raise ValueError(
                f"{spec.name} record {index}: missing {column}"
            ) from None
    if value is None or value == "":
        if column in spec.date_fields:
            value = when.strftime(spec.date_fields[column])
        else:
            value = ""
    text = str(value)
    if column.lower() in {"update_type"} or column == "UPDATE_TYPE":
        text = text.strip().upper()
        if text not in UPDATE_TYPES:
            raise ValueError(
                f"{spec.name} record {index}: update_type must be A, D, or M (got {text!r})"
            )
    if "|" in text:
        raise ValueError(
            f"{spec.name} record {index}: column {column} contains '|'"
        )
    return text


def render_table(spec: TableSpec, records: list, when: datetime) -> str:
    lines = ["|".join(spec.header)]
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"{spec.name} record {index}: expected an object")
        cells = [_cell(record, column, spec, when, index) for column in spec.header]
        lines.append("|".join(cells))
    return "\n".join(lines) + "\n"


def load_cmdb(path: Path) -> dict[str, list]:
    data = load_json(Path(path))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: CMDB input must be an object keyed by dataset name")
    unknown = sorted(set(data) - set(TABLES))
    if unknown:
        known = ", ".join(TABLES)
        raise ValueError(
            f"{path}: unknown dataset(s) {', '.join(unknown)}. Known: {known}"
        )
    loaded: dict[str, list] = {}
    for name, records in data.items():
        if records is None:
            records = []
        if not isinstance(records, list):
            raise ValueError(f"{path}: {name} must be a list of records")
        loaded[name] = records
    return loaded


def write_cmdb(
    changes: dict[str, list],
    base_directory: Path,
    now: datetime,
    force: bool = False,
) -> list[dict]:
    """Write one gzip file per non-empty dataset. All files share the run tag."""
    tag = format_tag(now)
    written: list[dict] = []
    for name, spec in TABLES.items():
        if name not in changes:
            continue
        records = changes[name]
        if not records:
            print(f"[cmdb] {name}: no records, skipped", flush=True)
            continue
        text = render_table(spec, records, now)
        dest = Path(base_directory) / spec.directory / spec.filename.format(tag=tag)
        info = write_gz(dest, text, force=force)
        info.update({"kind": "cmdb", "dataset": name, "tag": tag, "records": len(records)})
        written.append(info)
        print(f"[cmdb] {name}: records={len(records)} -> {dest}", flush=True)
    return written
