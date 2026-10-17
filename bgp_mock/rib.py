"""Pipe-delimited BGP dump lines and route-target filtering.

Column indexes follow the engine2 parser used by drop_idl.py and the
RR-migration update notebook:

    0 op, 1 timestamp, 3 source, 4 peer ASN, 7 NLRI, 8 AS path,
    9 origin, 10 nexthop, 11 local pref, 12 MED, 13 community,
    14 extended community, 18 originator, 19 cluster list
"""

from __future__ import annotations

import json
import re
from pathlib import Path

IDX_OP = 0
IDX_TS = 1
IDX_SOURCE = 3
IDX_PEER_ASN = 4
IDX_NLRI = 7
IDX_AS_PATH = 8
IDX_ORIGIN = 9
IDX_NEXTHOP = 10
IDX_LOCAL_PREF = 11
IDX_MED = 12
IDX_COMMUNITY = 13
IDX_EXT = 14
IDX_ATOMIC = 15
IDX_AGG_ADDR = 16
IDX_AGG_AS = 17
IDX_ORIGINATOR = 18
IDX_CLUSTER = 19
L3VPN_LABEL = "16001"

MIN_TOKENS = 20
SNAPSHOT_OPS = frozenset({"R", "A"})

SAFI_INET = "1"
SAFI_IDL = "4"
SAFI_VPLS = "65"
SAFI_L3VPN = "128"
SAFI_RTC = "132"

IDL_ORIGIN_KEEP = "INCOMPLETE"
IDL_ASN_KEEP = "4210010000"
IDL_COMM_INCLUDE = (":8218",)
IDL_COMM_EXCLUDE = (":8208", ":8217", ":3102")

FIELD_INDEX = {
    "op": IDX_OP,
    "timestamp": IDX_TS,
    "source": IDX_SOURCE,
    "peer_asn": IDX_PEER_ASN,
    "nlri": IDX_NLRI,
    "as_path": IDX_AS_PATH,
    "origin": IDX_ORIGIN,
    "nexthop": IDX_NEXTHOP,
    "local_pref": IDX_LOCAL_PREF,
    "med": IDX_MED,
    "community": IDX_COMMUNITY,
    "ext_community": IDX_EXT,
    "atomic_aggregate": IDX_ATOMIC,
    "aggregator_address": IDX_AGG_ADDR,
    "aggregator_as": IDX_AGG_AS,
    "originator": IDX_ORIGINATOR,
    "cluster": IDX_CLUSTER,
}

_RT_TOKEN = re.compile(r"(\d+):(\d+)")

# A realistic RTC advertisement. Synthetic prefixes clone this row, then overlay NLRI.
BUILTIN_TEMPLATE = (
    "A|2026-09-03+12:00:00|000000|32.130.198.49|13979|0.0.0.0|0|"
    "1,132;7018,2,13979:100298/96||IGP|32.130.198.49|100|0|13979:7091||NAG|"
    "0.0.0.0|0|32.130.198.49|4.0.11.0|||1||"
)


def split_line(raw: str) -> list[str] | None:
    """Return columns, or None when the row is too short to be a route."""
    if not raw or raw.startswith("#"):
        return None
    tokens = raw.rstrip("\n").split("|")
    if len(tokens) < MIN_TOKENS:
        return None
    return tokens


def join_line(tokens: list[str]) -> str:
    return "|".join(tokens)


def ensure_width(tokens: list[str], index: int) -> None:
    if index >= len(tokens):
        tokens.extend([""] * (index + 1 - len(tokens)))


def afi_safi(nlri: str) -> tuple[str, str]:
    """First NLRI segment is `afi,safi`."""
    head = (nlri or "").split(";")[0]
    parts = head.split(",")
    if len(parts) < 2:
        return "", ""
    return parts[0].strip(), parts[1].strip()


def normalize_rt(raw: str) -> str:
    """Accept `13979:717968`, `RT:13979:717968`, and `RT,13979,717968`."""
    text = str(raw or "").strip()
    if not text:
        return ""
    if "," in text and "RT" in text.upper():
        found = rts_from_ext(text)
        return found[0] if found else ""
    if text.upper().startswith("RT:"):
        text = text[3:]
    return text.strip()


def rts_from_ext(ext: str) -> list[str]:
    """Engine2 Parser.getRTs: token `RT,asn,num` becomes `asn:num`."""
    found: list[str] = []
    for community in (ext or "").split():
        if "RT" not in community.upper():
            continue
        values = community.split(",")
        if len(values) < 3:
            continue
        rt = values[1] + ":" + values[2]
        if rt:
            found.append(rt)
    return found


def rts_from_rtc_nlri(nlri: str) -> list[str]:
    """SAFI 132 encodes the route target inside the NLRI (`13979:100298/96`)."""
    return [f"{asn}:{num}" for asn, num in _RT_TOKEN.findall(nlri or "")]


def line_rts(tokens: list[str]) -> list[str]:
    nlri = tokens[IDX_NLRI] if len(tokens) > IDX_NLRI else ""
    _afi, safi = afi_safi(nlri)
    found: list[str] = []
    if safi == SAFI_RTC:
        found.extend(rts_from_rtc_nlri(nlri))
    ext = tokens[IDX_EXT] if len(tokens) > IDX_EXT else ""
    found.extend(rts_from_ext(ext))
    return found


def _rt_values(value) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            rt = normalize_rt(str(item))
            if rt:
                out.append(rt)
        return out
    rt = normalize_rt(str(value))
    return [rt] if rt else []


def load_rt_allowlist(path: Path) -> set[str]:
    """JSON list, JSON object, or one RT per line. `#` starts a comment."""
    raw = Path(path).read_text(encoding="utf-8")
    stripped = raw.strip()
    allow: set[str] = set()
    if stripped.startswith("[") or stripped.startswith("{"):
        data = json.loads(stripped)
        if isinstance(data, dict):
            picked = None
            for key in ("rts", "rt", "allow", "allowlist", "items"):
                if key in data:
                    picked = data[key]
                    break
            data = picked if picked is not None else list(data.keys())
        if not isinstance(data, list):
            data = [data]
        for item in data:
            if isinstance(item, dict):
                for key in ("rt", "RT", "route_target", "rts"):
                    if key in item:
                        allow.update(_rt_values(item.get(key)))
                        break
            else:
                allow.update(_rt_values(item))
        return allow
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower() in {"rt", "route_target", "rts"}:
            continue
        allow.update(_rt_values(line))
    return allow


def idl_community_drop(community: str) -> bool:
    """True means drop. `:8218` keeps the row even when an exclude token is present."""
    text = community or ""
    for token in IDL_COMM_INCLUDE:
        if token in text:
            return False
    for token in IDL_COMM_EXCLUDE:
        if token in text:
            return True
    return False


def keep_idl_session(tokens: list[str]) -> bool:
    """Engine2 IDLHandler.parseLine gates for SAFI 4."""
    if tokens[IDX_ORIGIN] != IDL_ORIGIN_KEEP:
        return False
    if tokens[IDX_PEER_ASN] != IDL_ASN_KEEP:
        return False
    community = tokens[IDX_COMMUNITY] if len(tokens) > IDX_COMMUNITY else ""
    if idl_community_drop(community):
        return False
    return True


def classify(tokens: list[str], allow: set[str], keep_idl: bool = True) -> str:
    """Return keep_* or drop_* / skip.

    L3VPN (SAFI 128) matches extended-community RTs.
    RTC (SAFI 132) matches the RT embedded in the NLRI.
    IDL (SAFI 4) uses the engine2 session gates when keep_idl is true.
    Internet (SAFI 1) and VPLS (SAFI 65) are always dropped.
    """
    if tokens[IDX_OP] not in SNAPSHOT_OPS:
        return "skip"
    _afi, safi = afi_safi(tokens[IDX_NLRI] if len(tokens) > IDX_NLRI else "")
    if safi == SAFI_INET:
        return "drop_inet"
    if safi == SAFI_VPLS:
        return "drop_vpls"
    if safi == SAFI_IDL:
        if not keep_idl:
            return "drop_idl"
        return "keep_idl" if keep_idl_session(tokens) else "drop_idl"
    matched = set(line_rts(tokens)) & allow
    if safi == SAFI_L3VPN:
        return "keep_l3vpn" if matched else "drop_l3vpn"
    if safi == SAFI_RTC:
        return "keep_rtc" if matched else "drop_rtc"
    if matched:
        return "keep_rt"
    return "skip"


def prefix_of(nlri: str) -> str:
    """Best-effort unicast prefix from an NLRI cell."""
    for part in reversed((nlri or "").replace(",", ";").split(";")):
        part = part.strip()
        if "/" in part and ":" not in part.split("/")[0]:
            return part.split()[-1]
    return ""


def rd_for_nlri(rd: str) -> str:
    """Write a two-part `asn:num` RD as `asn,num`.

    A comma RD, or a type-0 RD such as `0:13979:1080400`, stays as given.
    """
    text = str(rd).strip()
    if "," in text or text.count(":") != 1:
        return text
    asn, num = text.split(":", 1)
    if not asn.isdigit() or not num.isdigit():
        return text
    return f"{asn},{num}"


def set_rt(tokens: list[str], rt: str) -> None:
    """Write one `RT,asn,num` extended community.

    SAFI 132 also receives the same asn:num inside the NLRI.
    """
    normalized = normalize_rt(rt)
    if ":" not in normalized:
        raise ValueError(f"RT must look like asn:num, got {rt!r}")
    asn, num = normalized.split(":", 1)
    ensure_width(tokens, IDX_EXT)
    tokens[IDX_EXT] = f"RT,{asn},{num}"
    nlri = tokens[IDX_NLRI]
    _afi, safi = afi_safi(nlri)
    if safi == SAFI_RTC:
        updated, count = _RT_TOKEN.subn(normalized, nlri, count=1)
        tokens[IDX_NLRI] = updated if count else nlri


def apply_set(tokens: list[str], values: dict | None) -> None:
    """Copy named columns onto a row. Unknown keys are an error."""
    if not values:
        return
    for key, value in values.items():
        if key not in FIELD_INDEX:
            raise ValueError(
                f"unknown column {key!r}. Known columns: {', '.join(sorted(FIELD_INDEX))}"
            )
        index = FIELD_INDEX[key]
        ensure_width(tokens, index)
        tokens[index] = "" if value is None else str(value)


def _bump_int(current: str, delta: int, fallback: int) -> str:
    try:
        return str(int(float(current or "0")) + int(delta))
    except (TypeError, ValueError):
        return str(fallback)


def _prepend_as_path(path: str, asn: str, hops: int) -> str:
    old = (path or "").strip()
    prefix = " ".join([str(asn)] * int(hops))
    if not prefix:
        return old
    return f"{prefix} {old}".strip() if old else prefix


def _set_last_asn(path: str, asn: str) -> str:
    parts = [item for item in (path or "").split() if item]
    if parts:
        parts[-1] = str(asn)
    else:
        parts = [str(asn)]
    return " ".join(parts)


def apply_attributes(tokens: list[str], attributes: dict | None) -> None:
    """Apply the anomaly attribute edits used by the RR-migration notebook.

    Supported keys: nexthop, local_pref, local_pref_delta, med, med_delta,
    community, community_add, origin, as_path, prepend_asn, prepend_hops,
    origin_asn, ext_community, rt, source, originator, cluster, peer_asn.
    """
    if not attributes:
        return
    attrs = dict(attributes)
    ensure_width(tokens, IDX_CLUSTER)

    direct = {
        "nexthop": IDX_NEXTHOP,
        "source": IDX_SOURCE,
        "originator": IDX_ORIGINATOR,
        "cluster": IDX_CLUSTER,
        "origin": IDX_ORIGIN,
        "as_path": IDX_AS_PATH,
        "community": IDX_COMMUNITY,
        "ext_community": IDX_EXT,
        "peer_asn": IDX_PEER_ASN,
        "local_pref": IDX_LOCAL_PREF,
        "med": IDX_MED,
    }
    for key, index in direct.items():
        if key in attrs and attrs[key] is not None:
            tokens[index] = str(attrs[key])

    if "local_pref" not in attrs and attrs.get("local_pref_delta") is not None:
        tokens[IDX_LOCAL_PREF] = _bump_int(tokens[IDX_LOCAL_PREF], attrs["local_pref_delta"], 150)
    if "med" not in attrs and attrs.get("med_delta") is not None:
        tokens[IDX_MED] = _bump_int(tokens[IDX_MED], attrs["med_delta"], 100)
    if attrs.get("community_add"):
        extra = str(attrs["community_add"]).strip()
        current = (tokens[IDX_COMMUNITY] or "").strip()
        tokens[IDX_COMMUNITY] = f"{current} {extra}".strip() if current else extra
    hops = attrs.get("prepend_hops")
    if attrs.get("prepend_asn") and hops:
        tokens[IDX_AS_PATH] = _prepend_as_path(tokens[IDX_AS_PATH], attrs["prepend_asn"], int(hops))
    if attrs.get("origin_asn"):
        tokens[IDX_AS_PATH] = _set_last_asn(tokens[IDX_AS_PATH], attrs["origin_asn"])
    if attrs.get("rt"):
        set_rt(tokens, str(attrs["rt"]))


def materialize_prefix(item: dict, template: str) -> str:
    """Build one route row from a prefix description and a template line."""
    tokens = split_line(template)
    if tokens is None:
        raise ValueError("template line is not a BGP dump row")
    tokens = tokens[:]
    safi = str(item.get("safi") or "128")
    afi = str(item.get("afi") or "1")
    if item.get("nlri"):
        tokens[IDX_NLRI] = str(item["nlri"])
    elif safi == SAFI_RTC:
        rt = item.get("rt")
        if not rt:
            raise ValueError("SAFI 132 prefix needs rt")
        origin_as = item.get("origin_as", "7018")
        tokens[IDX_NLRI] = f"1,132;{origin_as},2,{normalize_rt(str(rt))}/96"
    elif safi == SAFI_L3VPN:
        prefix = item.get("prefix")
        if not prefix:
            raise ValueError("prefix requires prefix or nlri")
        rd = rd_for_nlri(str(item.get("rd") or item.get("rt") or "13979:1"))
        label = item.get("label") or L3VPN_LABEL
        # cloudstorage reads RD at semicolon [1] and the prefix at semicolon [3].
        tokens[IDX_NLRI] = f"{afi},{safi};{rd};{label};{prefix}"
    else:
        prefix = item.get("prefix")
        if not prefix:
            raise ValueError("prefix requires prefix or nlri")
        # Inet: cloudstorage reads the prefix at semicolon [1].
        tokens[IDX_NLRI] = f"{afi},{safi};{prefix}"
    if item.get("rt") and safi == SAFI_L3VPN:
        set_rt(tokens, str(item["rt"]))
    column_values = {key: item[key] for key in FIELD_INDEX if key in item and key != "nlri"}
    apply_set(tokens, column_values)
    if not item.get("nlri") and safi in {SAFI_L3VPN, SAFI_INET}:
        _fill_path_columns(tokens, item)
        if safi == SAFI_INET:
            tokens[IDX_EXT] = ""
    return join_line(tokens)


def _fill_path_columns(tokens: list[str], item: dict) -> None:
    """Match the update column layout: empty unused fields, cluster = source."""
    ensure_width(tokens, IDX_CLUSTER)
    for index in (2, IDX_PEER_ASN, 5, 6):
        tokens[index] = ""
    if "community" not in item:
        tokens[IDX_COMMUNITY] = ""
    if "nexthop" not in item:
        tokens[IDX_NEXTHOP] = tokens[IDX_ORIGINATOR] or tokens[IDX_SOURCE]
    if "atomic_aggregate" not in item:
        tokens[IDX_ATOMIC] = ""
    if "aggregator_address" not in item:
        tokens[IDX_AGG_ADDR] = ""
    if "aggregator_as" not in item:
        tokens[IDX_AGG_AS] = ""
    if "cluster" not in item:
        tokens[IDX_CLUSTER] = tokens[IDX_SOURCE]
    if not (tokens[IDX_AS_PATH] or "").strip() and item.get("rt"):
        asn = normalize_rt(str(item["rt"])).split(":", 1)[0]
        if asn:
            tokens[IDX_AS_PATH] = asn
    del tokens[IDX_CLUSTER + 1 :]


def row_matches(tokens: list[str], select: dict) -> bool:
    """True when a dump row satisfies the action select block."""
    ops = select.get("ops") or ["R", "A"]
    if tokens[IDX_OP] not in set(ops):
        return False
    _afi, safi = afi_safi(tokens[IDX_NLRI])
    if select.get("safi") and safi != str(select["safi"]):
        return False
    if select.get("source") and tokens[IDX_SOURCE] != str(select["source"]):
        return False
    if select.get("originator") and tokens[IDX_ORIGINATOR] != str(select["originator"]):
        return False
    wanted_rts = select.get("rts") or select.get("rt")
    if wanted_rts:
        allow = set()
        for item in wanted_rts if isinstance(wanted_rts, list) else [wanted_rts]:
            rt = normalize_rt(str(item))
            if rt:
                allow.add(rt)
        if not (set(line_rts(tokens)) & allow):
            return False
    wanted_prefix = select.get("prefix") or select.get("prefixes")
    if wanted_prefix:
        wanted = wanted_prefix if isinstance(wanted_prefix, list) else [wanted_prefix]
        wanted = {str(item) for item in wanted}
        nlri = tokens[IDX_NLRI]
        if prefix_of(nlri) not in wanted and not any(item in nlri for item in wanted):
            return False
    contains = select.get("nlri_contains")
    if contains and str(contains) not in tokens[IDX_NLRI]:
        return False
    return True
