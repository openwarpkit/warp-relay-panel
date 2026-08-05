import unittest

from relay_audit import ServerConfig, build_markdown, summarize_server


def raw_fixture(kind="full", flow_mark=7, nft_mark=7, class_mark=7, class_rate=10.0):
    health = {
        "version": "test",
        "uptime_seconds": 100,
        "online_clients": 1,
        "memory_mb": {"used": 100, "total": 1000},
        "disk": {"percent": 10},
    }
    control = {"items": [{"ip": "198.51.100.10", "mark": 7, "mbps": 10}]}
    if kind == "min":
        health["shared_limit"] = {"mbps": 10}
        health["traffic_ips"] = 0
        control = {"items": [{"ip": "198.51.100.10", "mark": 7}], "idle_grace": 60}
    snapshot = {
        "clients": {
            "198.51.100.10": {
                "flows": 1,
                "marks": [flow_mark],
                "orig_bytes": 100,
                "reply_bytes": 1000,
            }
        },
        "flows": 1,
        "nft_map": {"198.51.100.10": nft_mark},
        "tc_classes": {
            str(class_mark): {
                "mbps": class_rate,
                "bytes": 1100,
                "packets": 10,
                "dropped": 0,
                "overlimits": 2,
            },
            "65535": {"mbps": 1000, "bytes": 0, "packets": 0, "dropped": 0, "overlimits": 0},
        },
    }
    return {
        "kind": kind,
        "health": health,
        "control": control,
        "kernel": {"first": snapshot, "second": snapshot},
        "rules": {
            "qdisc_htb": True,
            "flow_filter": True,
            "nft_mark_rule": True,
            "restore_mark": True,
            "nat": True,
            "min_forward_out": True,
            "min_forward_in": True,
            "full_forward_out": True,
            "full_forward_in": True,
            "full_drop": True,
        },
        "system": {
            "service": {"ActiveState": "active"},
            "ipset_rules_writable": True,
            "ip_forward": 1,
            "conntrack_count": 1,
            "conntrack_max": 100,
            "cpu": {"busy": 5, "steal": 0},
            "network_sample": {"rx_mbps": 10, "tx_mbps": 10, "drop_delta": 0},
        },
        "stats": {
            "traffic": {
                "month": "2026-08",
                "total_tx_bytes": 100,
                "total_rx_bytes": 1000,
                "ip_count": 1,
            },
            "network": {"tx_bytes_total": 2000, "rx_bytes_total": 2010},
        },
        "journal": {
            "failures": 0,
            "other_failures": 0,
            "ipset_persist_failed": 0,
            "self_sync_failed": 0,
            "ipset_swap_error": 0,
            "command_failed": 0,
            "drift": 0,
            "restore_all": 0,
            "self_heal": 0,
        },
    }


class RelayAuditTests(unittest.TestCase):
    def test_full_rate_path_passes(self):
        server = ServerConfig("full", "example", "full")
        summary = summarize_server(server, raw_fixture(), False, "salt")
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["kernel"]["persistent_zero_mark"], 0)
        self.assertEqual(summary["kernel"]["overlimit_classes"], 1)

    def test_min_stale_agent_mark_is_warning_when_effective_rate_is_correct(self):
        server = ServerConfig("min", "example", "min", expected_limit_mbps=10)
        raw = raw_fixture("min", flow_mark=12, nft_mark=12, class_mark=12, class_rate=10)
        raw["kernel"]["first"]["tc_classes"]["7"] = {"mbps": 10}
        raw["kernel"]["second"]["tc_classes"]["7"] = {"mbps": 10}
        summary = summarize_server(server, raw, False, "salt")
        self.assertEqual(summary["status"], "warn")
        self.assertEqual(summary["kernel"]["persistent_map_mismatch"], 1)
        self.assertEqual(summary["kernel"]["persistent_effective_rate_mismatch"], 0)

    def test_persistent_zero_mark_fails(self):
        server = ServerConfig("min", "example", "min", expected_limit_mbps=10)
        summary = summarize_server(server, raw_fixture("min", flow_mark=0), False, "salt")
        self.assertEqual(summary["status"], "fail")
        codes = {item["code"] for item in summary["findings"]}
        self.assertIn("zero_mark", codes)

    def test_markdown_contains_traffic_explanation(self):
        server = ServerConfig("full", "example", "full")
        summary = summarize_server(server, raw_fixture(), False, "salt")
        report = {
            "generated_at": "now",
            "status": "pass",
            "servers": [summary],
            "global_findings": [],
        }
        markdown = build_markdown(report)
        self.assertIn("one-interface relay", markdown)
        self.assertIn("conntrack original/reply", markdown)


if __name__ == "__main__":
    unittest.main()
