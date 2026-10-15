"""Timestamps shared by dump filenames and BGP line clocks."""

from __future__ import annotations

from datetime import datetime, timezone


def as_utc(value: datetime | None = None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def parse_now(value: str | None) -> datetime:
    """ISO-8601 timestamp. A missing value means the current UTC minute."""
    if not value:
        return as_utc()
    text = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return as_utc(parsed)


def format_bgp_ts(value: datetime) -> str:
    """Engine2 routeFeedTimeFormat: YYYY-MM-DD+HH:MM:SS."""
    stamp = as_utc(value)
    return stamp.strftime("%Y-%m-%d+%H:%M:%S")


def format_tag(value: datetime) -> str:
    """Mailbox filename stamp: YYYYMMDDHHMM."""
    return as_utc(value).strftime("%Y%m%d%H%M")
