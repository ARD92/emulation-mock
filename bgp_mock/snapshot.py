"""Filter a BGP dump by route target and stamp it into the recent window."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from bgp_mock.io_util import open_text, write_gz_lines
from bgp_mock.rib import IDX_TS, classify, split_line
from bgp_mock.timeutil import format_bgp_ts, format_tag

DUMP_DIR = Path("lrsi-data/bgp/dumps/text")
PROGRESS_EVERY = 1_000_000


def snapshot_timestamp(now: datetime, minutes_ago: int) -> datetime:
    """Place the snapshot inside the requested lookback. Default callers use 45."""
    if minutes_ago < 0:
        raise ValueError("snapshot_minutes_ago must be >= 0")
    return (now - timedelta(minutes=int(minutes_ago))).replace(microsecond=0)


def filter_snapshot(
    source: Path,
    allow: set[str],
    base_directory: Path,
    now: datetime,
    minutes_ago: int = 45,
    keep_idl: bool = True,
    force: bool = False,
) -> dict:
    """Stream source, keep matching rows, rewrite the timestamp, write the gz."""
    if not allow:
        raise ValueError("RT allowlist is empty. Refusing to write an empty snapshot.")
    if not Path(source).is_file():
        raise FileNotFoundError(f"snapshot source not found: {source}")

    stamped = snapshot_timestamp(now, minutes_ago)
    tag = format_tag(stamped)
    line_ts = format_bgp_ts(stamped)
    dest = Path(base_directory) / DUMP_DIR / f"{tag}.txt.gz"

    stats = {
        "n_in": 0,
        "n_out": 0,
        "keep_l3vpn": 0,
        "keep_rtc": 0,
        "keep_idl": 0,
        "keep_rt": 0,
        "drop_l3vpn": 0,
        "drop_rtc": 0,
        "drop_idl": 0,
        "drop_inet": 0,
        "drop_vpls": 0,
        "skip": 0,
    }
    def kept_lines():
        with open_text(source) as handle:
            for line in handle:
                raw = line.rstrip("\n")
                if not raw:
                    continue
                stats["n_in"] += 1
                tokens = split_line(raw)
                if tokens is None:
                    stats["skip"] += 1
                    continue
                kind = classify(tokens, allow, keep_idl=keep_idl)
                stats[kind] = stats.get(kind, 0) + 1
                if kind.startswith("keep_"):
                    tokens[IDX_TS] = line_ts
                    stats["n_out"] += 1
                    yield "|".join(tokens)
                if stats["n_in"] % PROGRESS_EVERY == 0:
                    print(
                        f"[snapshot] processed={stats['n_in']:,} kept={stats['n_out']:,}",
                        flush=True,
                    )

    written = write_gz_lines(dest, kept_lines(), force=force)
    written.update(
        {
            "kind": "snapshot",
            "tag": tag,
            "line_ts": line_ts,
            "minutes_ago": int(minutes_ago),
            "source": str(source),
            "allowlist_n": len(allow),
            "keep_idl": keep_idl,
            "stats": stats,
        }
    )
    print(
        f"[snapshot] kept={stats['n_out']:,} of {stats['n_in']:,} -> {dest}",
        flush=True,
    )
    return written
