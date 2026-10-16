# BGP mock generator

Generates mailbox files for BGP anomaly tests. A scenario file points at the inputs. Each input owns one kind of change, so a new case is another record in that file.

## What it writes

| Section | Output |
|---|---|
| Filtered snapshot | `{base}/lrsi-data/bgp/dumps/text/YYYYMMDDHHMM.txt.gz` |
| BGP updates | `{base}/lrsi-data/bgp/updates/text/YYYYMMDDHHMM.txt.gz` |
| `bgp_cmdb` | `{base}/netdb-data/bgp/updates/Loopback_to_RouterName_YYYYMMDDHHMM.txt.gz` |
| `session_limit_cmdb` | `{base}/netdb-data/prefix_limits/updates/Session_Limits_YYYYMMDDHHMM.txt.gz` |
| `vrf_limits` | `{base}/netdb-data/prefix_limits/updates/VRF_Limits_YYYYMMDDHHMM.txt.gz` |
| `rr_plane_cmdb` | `{base}/netdb-data/prefix_limits/updates/RR_Plane_Cluster_YYYYMMDDHHMM.txt.gz` |
| `rt_limits` | `{base}/netdb-data/prefix_limits/updates/RT_Limits_cmdb_YYYYMMDDHHMM.txt.gz` |
| Config change | `{base}/netdb-data/config/updates/Config_Changes_YYYYMMDDHHMM.txt.gz` plus `*_baseline.cfg` and `*_modified.cfg` |

The snapshot clock is `snapshot_minutes_ago` before the run time. The default is 45 minutes, inside a 30 to 60 minute window. Update lines start at the run time. Each update action gets its own file so advertise, withdraw, flap, and attribute files stay apart.

A manifest of every file, line count, and MD5 is written to `{base}/mock-generator/latest.json`.

## Run

From this directory:

```bash
python3 generate.py run examples/scenario.json --base-directory /tmp/bgp-mock --force
```

The example scenario reads `examples/sample_rib.txt`. Point `snapshot.source` at a full dump (plain text or `.gz`) and `snapshot.rt_allowlist` at the RT list for a real run.

`bgp_updates.snapshot` set to `generated` reads the filtered snapshot. Point it at the original dump when an action must use rows the RT filter removed.

Individual sections:

```bash
python3 generate.py snapshot --base-directory /tmp/bgp-mock \
  --source /path/to/dump.txt.gz --rt-allowlist examples/rt_allowlist.txt

python3 generate.py cmdb --base-directory /tmp/bgp-mock --input examples/cmdb_changes.json

python3 generate.py updates --base-directory /tmp/bgp-mock \
  --input examples/bgp_updates.json --snapshot /tmp/bgp-mock/lrsi-data/bgp/dumps/text/<tag>.txt.gz

python3 generate.py config --base-directory /tmp/bgp-mock --input examples/config_changes.json

python3 generate.py datasets
```

`--now 2026-10-15T18:00:00+00:00` pins the clock. `--force` replaces files that already use that minute tag. Times are UTC.

## Snapshot filter

The RT list replaces the Mongo allowlist used by `drop_idl.py`. Accepted spellings are `13979:100499`, `RT:13979:100499`, and `RT,13979,100499`. A JSON list or object also works. An empty list writes nothing.

| SAFI | Keep rule |
|---|---|
| 128 L3VPN | Extended community contains an allowlisted RT (`RT,asn,num`) |
| 132 RTC | NLRI contains an allowlisted RT (`13979:100298/96`) |
| 4 IDL | Engine2 session gates: origin `INCOMPLETE`, ASN `4210010000`, community `:8218` before `:8208` / `:8217` / `:3102` |
| 1 and 65 | Dropped |

Set `"keep_idl": false` in the scenario, or pass `--no-idl`, to drop SAFI 4 as well. Kept rows keep their op (`R` or `A`). Only the timestamp is rewritten.

## CMDB input

`examples/cmdb_changes.json` is the template. Each key is a dataset. Each record is one inserted (`A`), deleted (`D`), or modified (`M`) row. Date columns are filled from the run clock when omitted.

- `bgp_cmdb` date is `YYYYMMDD`
- `session_limit_cmdb` and `vrf_limits` date is `YYYYMMDD`
- `rr_plane_cmdb` `file_date` is `YYYY-MM-DD`
- `rt_limits` date is `YYYYMMDD`

To add a dataset, append a `TableSpec` in `bgp_mock/cmdb.py` and put a list under that name in the CMDB input. `python3 generate.py datasets` prints the output path.

## BGP update input

`examples/bgp_updates.json` is three actions in one file. Each action writes its own gzip under `lrsi-data/bgp/updates/text/`.

### Advertise a prefix block

`prefix` is the subnet. The tool carves it into L3VPN routes (SAFI 128). `count` defaults to 100. `interval_seconds` defaults to 20, so each advertisement is 20 seconds after the previous one. `rt`, `rd`, `source`, and `originator_id` are required.

A /16 with count 100 becomes one hundred /24s, `10.50.0.0/24` through `10.50.99.0/24`. Set `prefix_length` when the carved length should be something else. One prefix (`count` 1) advertises the block itself.

### Withdraw those prefixes

`from_action` names an earlier action in the same file and withdraws those prefixes. `count` withdraws only the first N of them. Omit `count` to withdraw every prefix that action generated.

A withdraw can also name its own `prefix` block. That form uses the same required fields and the same count default of 100.

### Attribute changes

`attribute_change` edits the same earlier prefixes, or its own prefix block. `count` limits how many prefixes in that range are changed. `interval_seconds` is optional here. Set it when the attribute updates should be staggered.

Several attributes can be combined on one action:

- `nexthop`, `local_pref`, `local_pref_delta`, `med`, `med_delta`
- `as_path`, `prepend_asn`, `prepend_hops`, `origin_asn`
- `origin`, `community`, `community_add`, `ext_community`, `rt`
- `source`, `originator`, `cluster`, `peer_asn`

`select` still reads rows from a snapshot when an action has no `prefix` and no `from_action`. Select keys: `rts`, `safi`, `source`, `originator`, `prefix`, `nlri_contains`, `limit`, `unique_nlri` (default true), `ops` (default `R` and `A`). `flap` and `staggered` remain available for that snapshot path.

## Config changes

`examples/config_changes.json` carries `baseline_config` and `modified_config` for each router. `update_type` `M` requires both texts. `A` requires the modified text. `D` requires the baseline text.

The index gzip points at the two `.cfg` files. That path is `netdb-data/config/updates/` because a config mailbox path was not part of the CMDB layout.

## Tests

```bash
python3 -m unittest discover -s tests -v
```
