"""BGP update files: advertise, withdraw, flap, attribute change, staggered."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from bgp_mock.io_util import load_json, open_text, write_gz
from bgp_mock.prefixes import expand_prefix_block
from bgp_mock.rib import (
    BUILTIN_TEMPLATE,
    IDX_NLRI,
    apply_attributes,
    apply_set,
    join_line,
    materialize_prefix,
    row_matches,
    split_line,
)
from bgp_mock.timeutil import format_bgp_ts, format_tag

UPDATES_DIR = Path("lrsi-data/bgp/updates/text")
ACTION_TYPES = frozenset(
    {"advertise", "withdraw", "flap", "attribute_change", "staggered"}
)
DEFAULT_OP = {
    "advertise": "A",
    "withdraw": "W",
    "attribute_change": "A",
    "staggered": "A",
    "flap": "A",
}
BLOCK_TYPES = frozenset({"advertise", "withdraw", "attribute_change"})
DEFAULT_BLOCK_COUNT = 100
DEFAULT_ADVERTISE_INTERVAL = 20


def load_updates(path: Path) -> dict:
    data = load_json(Path(path))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: BGP update input must be an object")
    actions = data.get("actions")
    if not isinstance(actions, list) or not actions:
        raise ValueError(f"{path}: actions must be a non-empty list")
    for index, action in enumerate(actions, start=1):
        if not isinstance(action, dict):
            raise ValueError(f"action {index}: expected an object")
        kind = action.get("type")
        if kind not in ACTION_TYPES:
            known = ", ".join(sorted(ACTION_TYPES))
            raise ValueError(f"action {index}: type must be one of {known} (got {kind!r})")
    return data


def select_lines(source: Path, select: dict) -> list[str]:
    """Collect matching dump rows. `limit` stops the scan early."""
    if not select:
        return []
    limit = select.get("limit")
    unique = select.get("unique_nlri", True)
    found: list[str] = []
    seen: set[str] = set()
    with open_text(source) as handle:
        for line in handle:
            raw = line.rstrip("\n")
            tokens = split_line(raw)
            if tokens is None:
                continue
            if not row_matches(tokens, select):
                continue
            if unique:
                nlri = tokens[IDX_NLRI]
                if nlri in seen:
                    continue
                seen.add(nlri)
            found.append(raw)
            if limit is not None and len(found) >= int(limit):
                break
    return found


def _action_name(action: dict, index: int) -> str:
    return str(action.get("name") or f"{action['type']}-{index}")


def _count(action: dict, default: int | None) -> int | None:
    if "count" in action and action["count"] is not None:
        raw = action["count"]
    elif "num_prefixes" in action and action["num_prefixes"] is not None:
        raw = action["num_prefixes"]
    else:
        return default
    try:
        count = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"count must be an integer, got {raw!r}") from exc
    if count < 1:
        raise ValueError(f"count must be >= 1, got {count}")
    return count


def _block_cidr(action: dict) -> str:
    raw = action.get("prefix", action.get("subnet"))
    if raw is None:
        return ""
    return str(raw).strip()


def _is_prefix_block(action: dict) -> bool:
    cidr = _block_cidr(action)
    return "/" in cidr


def _identity(action: dict, name: str) -> tuple[str, str, str, str]:
    """RT, RD, source, and originator_id are required for a generated block."""
    originator = action.get("originator_id", action.get("originator"))
    fields = {
        "rt": action.get("rt"),
        "rd": action.get("rd"),
        "source": action.get("source"),
        "originator_id": originator,
    }
    missing = [key for key, value in fields.items() if value is None or str(value).strip() == ""]
    if missing:
        raise ValueError(f"action {name}: missing {', '.join(missing)}")
    return (
        str(fields["rt"]).strip(),
        str(fields["rd"]).strip(),
        str(fields["source"]).strip(),
        str(fields["originator_id"]).strip(),
    )


def _block_bases(action: dict, name: str) -> list[str]:
    if action["type"] not in BLOCK_TYPES:
        raise ValueError(f"action {name}: a prefix block is supported on advertise, withdraw, and attribute_change")
    rt, rd, source, originator = _identity(action, name)
    count = _count(action, DEFAULT_BLOCK_COUNT)
    length = action.get("prefix_length")
    if length is not None:
        length = int(length)
    prefixes = expand_prefix_block(_block_cidr(action), int(count), length)
    template = action.get("template_line") or BUILTIN_TEMPLATE
    bases: list[str] = []
    for prefix in prefixes:
        item = {
            "safi": "128",
            "prefix": prefix,
            "rd": rd,
            "rt": rt,
            "source": source,
            "originator": originator,
        }
        if action.get("nexthop"):
            item["nexthop"] = action["nexthop"]
        bases.append(materialize_prefix(item, template))
    return bases


def _from_action_bases(action: dict, name: str, produced: dict[str, list[str]]) -> list[str]:
    if _is_prefix_block(action):
        raise ValueError(f"action {name}: set from_action or prefix, not both")
    ref = str(action["from_action"])
    if ref not in produced:
        raise ValueError(f"action {name}: from_action {ref!r} is not an earlier action")
    rows = produced[ref]
    count = _count(action, None)
    if count is None:
        return list(rows)
    if count > len(rows):
        raise ValueError(
            f"action {name}: count {count} is larger than the {len(rows)} prefixes from {ref}"
        )
    return list(rows[:count])


def _bases_for(
    action: dict,
    snapshot: Path | None,
    index: int,
    produced: dict[str, list[str]] | None = None,
) -> list[str]:
    name = _action_name(action, index)
    if action.get("from_action"):
        return _from_action_bases(action, name, produced or {})
    if _is_prefix_block(action):
        return _block_bases(action, name)
    bases: list[str] = []
    select = action.get("select") or {}
    if select:
        if snapshot is None:
            raise ValueError(f"action {name}: select requires a snapshot file")
        bases.extend(select_lines(Path(snapshot), select))
    template = action.get("template_line") or BUILTIN_TEMPLATE
    for item in action.get("prefixes") or []:
        if not isinstance(item, dict):
            raise ValueError(f"action {name}: each prefix must be an object")
        bases.append(materialize_prefix(item, template))
    if not bases:
        raise ValueError(
            f"action {name}: no rows. Provide prefix/rt/rd/source/originator_id, "
            "from_action, or select plus a snapshot."
        )
    return bases


def _stamp(tokens: list[str], op: str, when: datetime) -> tuple[datetime, str]:
    out = tokens[:]
    out[0] = op
    out[1] = format_bgp_ts(when)
    return when, join_line(out)


def _prepare(base: str, action: dict) -> list[str]:
    tokens = split_line(base)
    if tokens is None:
        raise ValueError("internal: base row is not a BGP line")
    tokens = tokens[:]
    apply_set(tokens, action.get("set"))
    apply_attributes(tokens, action.get("attributes"))
    return tokens


def expand_action(action: dict, bases: list[str], start: datetime) -> list[tuple[datetime, str]]:
    """Turn one action into timestamped update lines."""
    kind = action["type"]
    name = action.get("name") or kind
    if "interval_seconds" in action and action["interval_seconds"] is not None:
        interval_seconds = float(action["interval_seconds"])
    elif kind == "advertise" and _is_prefix_block(action):
        interval_seconds = DEFAULT_ADVERTISE_INTERVAL
    else:
        interval_seconds = 0.0
    if kind == "staggered" and interval_seconds <= 0:
        raise ValueError(f"action {name}: staggered requires interval_seconds > 0")
    if kind == "flap" and interval_seconds <= 0:
        interval_seconds = 1
    interval = timedelta(seconds=interval_seconds)
    op = str(action.get("op") or DEFAULT_OP[kind]).upper()
    if kind != "flap" and op not in {"A", "W"}:
        raise ValueError(f"action {name}: op must be A or W")

    repeats = int(action.get("repeats") or 0)
    if kind == "flap" and repeats < 1:
        raise ValueError(f"action {name}: flap requires repeats >= 1")

    clock = start
    rows: list[tuple[datetime, str]] = []
    for base in bases:
        tokens = _prepare(base, action)
        if kind == "flap":
            for _ in range(repeats):
                rows.append(_stamp(tokens, "A", clock))
                clock += interval
                rows.append(_stamp(tokens, "W", clock))
                clock += interval
        else:
            rows.append(_stamp(tokens, op, clock))
            if interval_seconds > 0:
                clock += interval
    return rows


def _next_minute(value: datetime) -> datetime:
    trimmed = value.replace(second=0, microsecond=0)
    return trimmed + timedelta(minutes=1)


def write_updates(
    spec: dict,
    snapshot: Path | None,
    base_directory: Path,
    now: datetime,
    force: bool = False,
) -> list[dict]:
    """Write one gzip per action. File tags stay unique inside the run."""
    actions = spec["actions"]
    cursor = now.replace(microsecond=0)
    used_tags: set[str] = set()
    produced: dict[str, list[str]] = {}
    written: list[dict] = []
    for index, action in enumerate(actions, start=1):
        name = _action_name(action, index)
        if name in produced:
            raise ValueError(f"duplicate action name {name!r}")
        tag = format_tag(cursor)
        if tag in used_tags:
            cursor = _next_minute(cursor)
            tag = format_tag(cursor)
        bases = _bases_for(action, snapshot, index, produced)
        produced[name] = bases
        rows = expand_action(action, bases, cursor)
        if format_tag(rows[0][0]) != tag:
            raise RuntimeError(f"action {name}: file tag drifted from the first timestamp")
        body = "".join(line + "\n" for _ts, line in rows)
        dest = Path(base_directory) / UPDATES_DIR / f"{tag}.txt.gz"
        info = write_gz(dest, body, force=force)
        info.update(
            {
                "kind": "bgp_updates",
                "name": name,
                "type": action["type"],
                "tag": tag,
                "records": len(rows),
                "bases": len(bases),
                "first_ts": format_bgp_ts(rows[0][0]),
                "last_ts": format_bgp_ts(rows[-1][0]),
            }
        )
        written.append(info)
        used_tags.add(tag)
        cursor = rows[-1][0] + timedelta(seconds=1)
        print(
            f"[updates] {name} ({action['type']}): lines={len(rows)} -> {dest}",
            flush=True,
        )
    return written
