"""Checks for snapshot filtering, CMDB files, and BGP update actions."""

from __future__ import annotations

import gzip
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from bgp_mock.cmdb import load_cmdb, write_cmdb
from bgp_mock.io_util import read_text
from bgp_mock.prefixes import expand_prefix_block
from bgp_mock.rib import (
    IDX_AS_PATH,
    IDX_COMMUNITY,
    IDX_LOCAL_PREF,
    IDX_MED,
    IDX_NEXTHOP,
    IDX_OP,
    IDX_ORIGINATOR,
    IDX_SOURCE,
    IDX_TS,
    classify,
    load_rt_allowlist,
    split_line,
)
from bgp_mock.updates import write_updates
from bgp_mock.scenario import run_scenario
from bgp_mock.snapshot import filter_snapshot

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
NOW = datetime(2026, 10, 15, 18, 0, tzinfo=timezone.utc)


def _rows(path: Path) -> list[str]:
    text = read_text(path)
    return [line for line in text.splitlines() if line]


def _prefix(line: str) -> str:
    return line.split("|")[7].split(";")[-1]


class AllowlistAndClassifyTest(unittest.TestCase):
    def test_allowlist_spellings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rts.txt"
            path.write_text(
                "# comment\n13979:717968\nRT:13979:100499\nRT,13979,100298\n",
                encoding="utf-8",
            )
            self.assertEqual(
                load_rt_allowlist(path),
                {"13979:717968", "13979:100499", "13979:100298"},
            )

    def test_sample_rib_keeps_only_matching_routes(self):
        allow = load_rt_allowlist(EXAMPLES / "rt_allowlist.txt")
        kinds = []
        for line in (EXAMPLES / "sample_rib.txt").read_text().splitlines():
            tokens = split_line(line)
            self.assertIsNotNone(tokens)
            kinds.append(classify(tokens, allow, keep_idl=True))
        self.assertEqual(
            kinds,
            [
                "keep_l3vpn",
                "keep_l3vpn",
                "drop_l3vpn",
                "keep_rtc",
                "drop_inet",
                "drop_vpls",
                "keep_idl",
                "drop_idl",
            ],
        )

    def test_empty_allowlist_refuses_to_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                filter_snapshot(
                    source=EXAMPLES / "sample_rib.txt",
                    allow=set(),
                    base_directory=Path(tmp),
                    now=NOW,
                )


class ScenarioTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.manifest = run_scenario(
            EXAMPLES / "scenario.json",
            base_directory=self.base,
            now=NOW,
            force=True,
            minutes_ago=45,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _by_kind(self, kind: str) -> list[dict]:
        return [item for item in self.manifest["outputs"] if item["kind"] == kind]

    def test_snapshot_lands_in_the_30_to_60_minute_window(self):
        written = self._by_kind("snapshot")[0]
        self.assertEqual(written["tag"], "202610151715")
        self.assertEqual(written["line_ts"], "2026-10-15+17:15:00")
        self.assertEqual(written["stats"]["n_out"], 4)
        dest = Path(written["path"])
        self.assertEqual(
            dest,
            self.base / "lrsi-data/bgp/dumps/text/202610151715.txt.gz",
        )
        rows = _rows(dest)
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(row.split("|")[IDX_TS] == "2026-10-15+17:15:00" for row in rows))
        blob = "\n".join(rows)
        self.assertNotIn("10.2.0.0/24", blob)
        self.assertNotIn("1,1;10.9.0.0/8", blob)
        self.assertIn("13979:100298", blob)
        self.assertIn("10.1.0.0/24", blob)
        digest = hashlib.md5(dest.read_bytes()).hexdigest()
        self.assertEqual(digest, written["md5"])

    def test_cmdb_files_match_the_mailbox_layout(self):
        by_dataset = {item["dataset"]: item for item in self._by_kind("cmdb")}
        self.assertEqual(set(by_dataset), {
            "bgp_cmdb",
            "session_limit_cmdb",
            "vrf_limits",
            "rr_plane_cmdb",
            "rt_limits",
        })

        bgp = _rows(Path(by_dataset["bgp_cmdb"]["path"]))
        self.assertTrue(str(by_dataset["bgp_cmdb"]["path"]).endswith(
            "netdb-data/bgp/updates/Loopback_to_RouterName_202610151800.txt.gz"
        ))
        self.assertEqual(
            bgp[0],
            "interface_ip|router_name|router_date|network|loopback|interface_ip2|primary_ind|update_type",
        )
        self.assertEqual(
            bgp[1],
            "32.155.155.155|CL5OH555RV5|20261015|CBB|Loopback0||1|A",
        )
        self.assertTrue(bgp[2].endswith("|D"))

        session = _rows(Path(by_dataset["session_limit_cmdb"]["path"]))
        self.assertTrue(session[1].endswith("|20261015|A"))
        self.assertIn("BTMMD308ME1|32.155.155.155|VPNv4|import|5500000|75|teardown", session[1])

        vrf = _rows(Path(by_dataset["vrf_limits"]["path"]))
        self.assertTrue(vrf[0].startswith("network|router_name|vrf_name|"))
        self.assertIn("|M", vrf[1])

        rr = _rows(Path(by_dataset["rr_plane_cmdb"]["path"]))
        self.assertEqual(
            rr[1],
            "CBB|CGCIL162RV2|E|2.0.4.9|NC3|2026-10-15|M",
        )

        rt = _rows(Path(by_dataset["rt_limits"]["path"]))
        self.assertEqual(
            rt[0],
            "NETWORK|ROUTER_NAME|VRF_NAME|DIRECTION|RT|MAX_PREFIXES|MAX_PREFIX_THRESHOLD_PCT|THRESH_ACTION|DATE|UPDATE_TYPE",
        )
        self.assertIn("|13979:100499|", rt[1])
        self.assertTrue(rt[1].endswith("|A"))

    def test_update_actions(self):
        updates = self._by_kind("bgp_updates")
        by_name = {item["name"]: item for item in updates}
        self.assertEqual(
            [item["name"] for item in updates],
            ["advertise_block", "withdraw_block", "attribute_block"],
        )
        self.assertEqual(
            [item["tag"] for item in updates],
            ["202610151800", "202610151833", "202610151834"],
        )

        advertised = _rows(Path(by_name["advertise_block"]["path"]))
        self.assertEqual(len(advertised), 100)
        self.assertEqual([_prefix(row) for row in advertised[:2]], ["10.50.0.0/24", "10.50.1.0/24"])
        self.assertEqual(_prefix(advertised[-1]), "10.50.99.0/24")
        self.assertTrue(all(row.split("|")[IDX_OP] == "A" for row in advertised))
        first_ad = advertised[0].split("|")
        self.assertGreaterEqual(len(first_ad), 20)
        self.assertEqual(first_ad[IDX_SOURCE], "32.130.196.181")
        self.assertEqual(first_ad[IDX_ORIGINATOR], "12.123.71.144")
        self.assertEqual(first_ad[7], "1,128;13979:7285;22;10.50.0.0/24")
        self.assertEqual(first_ad[14], "RT_AS2,13979,7285")
        self.assertEqual(first_ad[IDX_NEXTHOP], "12.123.71.144")
        self.assertEqual(first_ad[13], "")
        self.assertEqual(first_ad[15], "AG")
        self.assertEqual(first_ad[16], "32.130.196.181")
        self.assertEqual(first_ad[17], "13979")
        self.assertEqual(first_ad[19], "12.123.71.144")
        self.assertEqual(advertised[0].split("|")[IDX_TS], "2026-10-15+18:00:00")
        self.assertEqual(advertised[1].split("|")[IDX_TS], "2026-10-15+18:00:20")
        self.assertEqual(advertised[-1].split("|")[IDX_TS], "2026-10-15+18:33:00")

        withdrawn = _rows(Path(by_name["withdraw_block"]["path"]))
        self.assertEqual(len(withdrawn), 40)
        self.assertEqual(
            [_prefix(row) for row in withdrawn],
            [_prefix(row) for row in advertised[:40]],
        )
        self.assertTrue(all(row.split("|")[IDX_OP] == "W" for row in withdrawn))
        self.assertTrue(all(row.split("|")[IDX_SOURCE] == "32.130.196.181" for row in withdrawn))

        shifted = _rows(Path(by_name["attribute_block"]["path"]))
        self.assertEqual(len(shifted), 25)
        first = shifted[0].split("|")
        self.assertEqual(first[IDX_OP], "A")
        self.assertEqual(first[IDX_NEXTHOP], "192.0.2.1")
        self.assertEqual(first[IDX_LOCAL_PREF], "150")
        self.assertEqual(first[IDX_MED], "100")
        self.assertTrue(first[IDX_AS_PATH].startswith("65000 65000 65000"))
        self.assertIn("65535:1", first[IDX_COMMUNITY])
        self.assertEqual(_prefix(shifted[0]), "10.50.0.0/24")
        self.assertEqual(_prefix(shifted[-1]), "10.50.24.0/24")
        self.assertEqual(shifted[0].split("|")[IDX_TS], "2026-10-15+18:34:00")
        self.assertEqual(shifted[1].split("|")[IDX_TS], "2026-10-15+18:34:20")

        for item in updates:
            path = Path(item["path"])
            self.assertTrue(str(path).endswith(f"lrsi-data/bgp/updates/text/{item['tag']}.txt.gz"))
            self.assertEqual(hashlib.md5(path.read_bytes()).hexdigest(), item["md5"])
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                self.assertEqual(sum(1 for _ in handle), item["records"])

    def test_config_writes_baseline_and_modified(self):
        written = self._by_kind("config_changes")[0]
        self.assertTrue(str(written["path"]).endswith(
            "netdb-data/config/updates/Config_Changes_202610151800.txt.gz"
        ))
        index = _rows(Path(written["path"]))
        self.assertEqual(
            index[0],
            "router_name|network|date|update_type|baseline_path|modified_path",
        )
        pair = written["files"][0]
        baseline = Path(pair["baseline_path"]).read_text(encoding="utf-8")
        modified = Path(pair["modified_path"]).read_text(encoding="utf-8")
        self.assertIn("neighbor 32.130.198.49", baseline)
        self.assertIn("maximum-prefix 100 75", modified)
        self.assertNotIn("maximum-prefix", baseline)
        self.assertTrue(index[1].startswith("ATNGA404ME9|CBB|20261015|M|"))

    def test_second_run_refuses_overwrite(self):
        with self.assertRaises(FileExistsError):
            run_scenario(
                EXAMPLES / "scenario.json",
                base_directory=self.base,
                now=NOW,
                force=False,
                minutes_ago=45,
            )


class PrefixBlockTest(unittest.TestCase):
    def test_block_defaults_to_slash_24_inside_the_subnet(self):
        prefixes = expand_prefix_block("10.50.0.0/16", 100)
        self.assertEqual(len(prefixes), 100)
        self.assertEqual(prefixes[0], "10.50.0.0/24")
        self.assertEqual(prefixes[-1], "10.50.99.0/24")

    def test_one_prefix_is_the_block_itself(self):
        self.assertEqual(expand_prefix_block("10.50.0.0/16", 1), ["10.50.0.0/16"])

    def _one(self, action: dict) -> str:
        with tempfile.TemporaryDirectory() as tmp:
            written = write_updates(
                {"actions": [action]},
                None,
                Path(tmp),
                NOW,
                force=True,
            )
            return _rows(Path(written[0]["path"]))[0]

    def test_inet_ipv4_uses_afi_1_safi_1(self):
        line = self._one({
            "name": "ads",
            "type": "advertise",
            "update_type": "inet",
            "ip_type": "ipv4",
            "prefix": "10.9.0.0/24",
            "count": 1,
            "interval_seconds": 0,
            "originator_id": "12.123.71.144",
            "source": "32.130.196.181",
        })
        tokens = line.split("|")
        self.assertEqual(tokens[7], "1,1;10.9.0.0/24")
        self.assertEqual(tokens[14], "")

    def test_inet_ipv6_uses_afi_2_safi_1(self):
        line = self._one({
            "name": "ads",
            "type": "advertise",
            "update_type": "inet",
            "ip_type": "ipv6",
            "prefix": "2001:db8::/32",
            "count": 1,
            "interval_seconds": 0,
            "originator_id": "2001:db8::1",
            "source": "2001:db8::2",
        })
        self.assertEqual(line.split("|")[7], "2,1;2001:db8::/32")

    def test_l3vpn_ipv6_uses_afi_2_safi_128(self):
        line = self._one({
            "name": "ads",
            "type": "advertise",
            "update_type": "l3vpn",
            "ip_type": "ipv6",
            "prefix": "2001:db8::/32",
            "count": 1,
            "interval_seconds": 0,
            "rt": "13979:7285",
            "rd": "13979:7285",
            "originator_id": "2001:db8::1",
            "source": "2001:db8::2",
        })
        tokens = line.split("|")
        self.assertEqual(tokens[7], "2,128;13979:7285;22;2001:db8::/32")
        self.assertEqual(tokens[14], "RT_AS2,13979,7285")

    def test_ip_type_must_match_the_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                write_updates(
                    {
                        "actions": [
                            {
                                "name": "ads",
                                "type": "advertise",
                                "update_type": "inet",
                                "ip_type": "ipv6",
                                "prefix": "10.9.0.0/24",
                                "count": 1,
                                "originator_id": "12.123.71.144",
                                "source": "32.130.196.181",
                            }
                        ]
                    },
                    None,
                    Path(tmp),
                    NOW,
                    force=True,
                )

    def test_missing_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec = {
                "actions": [
                    {
                        "name": "ads",
                        "type": "advertise",
                        "prefix": "10.50.0.0/16",
                        "count": 2,
                        "source": "32.130.196.181",
                    }
                ]
            }
            with self.assertRaises(ValueError) as caught:
                write_updates(spec, None, Path(tmp), NOW, force=True)
        self.assertIn("rt", str(caught.exception))
        self.assertIn("originator_id", str(caught.exception))

    def test_omitted_count_and_interval_use_the_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            written = write_updates(
                {
                    "actions": [
                        {
                            "name": "ads",
                            "type": "advertise",
                            "prefix": "10.9.0.0/16",
                            "rt": "13979:7285",
                            "rd": "13979:1",
                            "originator_id": "12.123.71.144",
                            "source": "32.130.196.181",
                        }
                    ]
                },
                None,
                Path(tmp),
                NOW,
                force=True,
            )
            self.assertEqual(written[0]["records"], 100)
            rows = _rows(Path(written[0]["path"]))
            self.assertEqual(rows[1].split("|")[IDX_TS], "2026-10-15+18:00:20")

    def test_withdraw_count_cannot_exceed_the_earlier_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                write_updates(
                    {
                        "actions": [
                            {
                                "name": "ads",
                                "type": "advertise",
                                "prefix": "10.9.0.0/24",
                                "count": 2,
                                "prefix_length": 32,
                                "rt": "13979:7285",
                                "rd": "13979:1",
                                "originator_id": "12.123.71.144",
                                "source": "32.130.196.181",
                                "interval_seconds": 0,
                            },
                            {
                                "name": "wds",
                                "type": "withdraw",
                                "from_action": "ads",
                                "count": 5,
                            },
                        ]
                    },
                    None,
                    Path(tmp),
                    NOW,
                    force=True,
                )


class CmdbInputTest(unittest.TestCase):
    def test_unknown_dataset_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cmdb.json"
            path.write_text(json.dumps({"not_a_dataset": []}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_cmdb(path)

    def test_bad_update_type_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            changes = {
                "bgp_cmdb": [
                    {
                        "interface_ip": "10.0.0.1",
                        "router_name": "R1",
                        "network": "CBB",
                        "loopback": "Loopback0",
                        "primary_ind": "1",
                        "update_type": "X",
                    }
                ]
            }
            with self.assertRaises(ValueError):
                write_cmdb(changes, Path(tmp), NOW, force=True)


if __name__ == "__main__":
    unittest.main()
