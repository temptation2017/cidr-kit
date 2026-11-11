#!/usr/bin/env python3
"""Unit tests for cidr_kit (stdlib unittest)."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import cidr_kit as ck


class ParseTests(unittest.TestCase):
    def test_bare_ipv4(self):
        net = ck.parse_network("192.0.2.15")
        self.assertEqual(str(net), "192.0.2.15/32")

    def test_host_bits_zeroed(self):
        net = ck.parse_network("192.0.2.15/24")
        self.assertEqual(str(net), "192.0.2.0/24")

    def test_ipv6(self):
        net = ck.parse_network("2001:db8::1")
        self.assertEqual(str(net), "2001:db8::1/128")

    def test_invalid(self):
        with self.assertRaises(ck.CidrError):
            ck.parse_network("999.1.1.1")
        with self.assertRaises(ck.CidrError):
            ck.parse_network("10.0.0.0/33")
        with self.assertRaises(ck.CidrError):
            ck.parse_network("")


class InfoTests(unittest.TestCase):
    def test_slash24(self):
        data = ck.info_data("192.0.2.0/24")
        self.assertEqual(data["cidr"], "192.0.2.0/24")
        self.assertEqual(data["broadcast"], "192.0.2.255")
        self.assertEqual(data["first_host"], "192.0.2.1")
        self.assertEqual(data["last_host"], "192.0.2.254")
        self.assertEqual(data["num_addresses"], 256)
        self.assertEqual(data["usable_hosts"], 254)
        self.assertEqual(data["netmask"], "255.255.255.0")
        self.assertEqual(data["wildcard"], "0.0.0.255")
        self.assertTrue(data["is_documentation"])
        self.assertFalse(data["host_bits_set"])

    def test_host_bits_note(self):
        data = ck.info_data("192.0.2.15/24")
        self.assertTrue(data["host_bits_set"])
        self.assertEqual(data["address"], "192.0.2.15")
        self.assertEqual(data["cidr"], "192.0.2.0/24")

    def test_slash32_and_31(self):
        d32 = ck.info_data("192.0.2.8/32")
        self.assertEqual(d32["usable_hosts"], 1)
        self.assertEqual(d32["first_host"], "192.0.2.8")
        d31 = ck.info_data("192.0.2.8/31")
        self.assertEqual(d31["usable_hosts"], 2)
        self.assertEqual(d31["first_host"], "192.0.2.8")
        self.assertEqual(d31["last_host"], "192.0.2.9")

    def test_ipv6_info(self):
        data = ck.info_data("2001:db8::/32")
        self.assertEqual(data["version"], 6)
        self.assertTrue(data["is_documentation"])
        self.assertIsNone(data["usable_hosts"])
        self.assertIn("last_address", data)
        self.assertNotIn("broadcast", data)


class RelationTests(unittest.TestCase):
    def test_contains(self):
        a = ck.parse_network("10.0.0.0/8")
        self.assertTrue(ck.contains(a, ck.parse_network("10.1.2.3")))
        self.assertTrue(ck.contains(a, ck.parse_network("10.1.0.0/16")))
        self.assertTrue(ck.contains(a, a))
        self.assertFalse(ck.contains(a, ck.parse_network("11.0.0.0/8")))
        self.assertFalse(ck.contains(ck.parse_network("10.1.0.0/16"), a))

    def test_overlap(self):
        self.assertTrue(
            ck.overlaps(ck.parse_network("10.0.0.0/16"), ck.parse_network("10.0.128.0/17"))
        )
        self.assertFalse(
            ck.overlaps(ck.parse_network("10.0.0.0/16"), ck.parse_network("10.1.0.0/16"))
        )
        # Adjacent, no overlap
        self.assertFalse(
            ck.overlaps(ck.parse_network("192.0.2.0/25"), ck.parse_network("192.0.2.128/25"))
        )

    def test_mix_versions(self):
        with self.assertRaises(ck.CidrError):
            ck.contains(ck.parse_network("10.0.0.0/8"), ck.parse_network("2001:db8::/32"))


class SplitSummarizeExcludeTests(unittest.TestCase):
    def test_split(self):
        nets = ck.split_network(ck.parse_network("192.0.2.0/24"), 26)
        self.assertEqual(
            [str(n) for n in nets],
            ["192.0.2.0/26", "192.0.2.64/26", "192.0.2.128/26", "192.0.2.192/26"],
        )

    def test_split_same(self):
        nets = ck.split_network(ck.parse_network("192.0.2.0/24"), 24)
        self.assertEqual([str(n) for n in nets], ["192.0.2.0/24"])

    def test_split_shorter_rejected(self):
        with self.assertRaises(ck.CidrError):
            ck.split_network(ck.parse_network("192.0.2.0/24"), 16)

    def test_split_cap(self):
        with self.assertRaises(ck.CidrError):
            ck.split_network(ck.parse_network("10.0.0.0/8"), 24)  # 65536 > 4096

    def test_summarize(self):
        nets = ck.summarize(
            [
                ck.parse_network("192.0.2.0/25"),
                ck.parse_network("192.0.2.128/25"),
            ]
        )
        self.assertEqual([str(n) for n in nets], ["192.0.2.0/24"])

    def test_summarize_overlap_and_dup(self):
        nets = ck.summarize(
            [
                ck.parse_network("10.0.0.0/24"),
                ck.parse_network("10.0.0.0/25"),
                ck.parse_network("10.0.1.0/24"),
            ]
        )
        self.assertEqual([str(n) for n in nets], ["10.0.0.0/23"])

    def test_summarize_mixed_families(self):
        nets = ck.summarize(
            [
                ck.parse_network("192.0.2.0/25"),
                ck.parse_network("2001:db8:1::/48"),
                ck.parse_network("192.0.2.128/25"),
                ck.parse_network("2001:db8:2::/48"),
            ]
        )
        self.assertEqual(
            [str(n) for n in nets],
            ["192.0.2.0/24", "2001:db8:1::/48", "2001:db8:2::/48"],
        )
        aligned = ck.summarize(
            [
                ck.parse_network("2001:db8::/48"),
                ck.parse_network("2001:db8:1::/48"),
            ]
        )
        self.assertEqual([str(n) for n in aligned], ["2001:db8::/47"])

    def test_exclude_inside(self):
        nets = ck.exclude(
            ck.parse_network("192.0.2.0/24"),
            [ck.parse_network("192.0.2.64/26")],
        )
        self.assertEqual(
            [str(n) for n in nets],
            ["192.0.2.0/26", "192.0.2.128/25"],
        )

    def test_exclude_equal(self):
        nets = ck.exclude(ck.parse_network("192.0.2.0/24"), [ck.parse_network("192.0.2.0/24")])
        self.assertEqual(nets, [])

    def test_exclude_outside(self):
        nets = ck.exclude(ck.parse_network("192.0.2.0/24"), [ck.parse_network("198.51.100.0/24")])
        self.assertEqual([str(n) for n in nets], ["192.0.2.0/24"])

    def test_exclude_multiple(self):
        nets = ck.exclude(
            ck.parse_network("10.0.0.0/16"),
            [ck.parse_network("10.0.1.0/24"), ck.parse_network("10.0.2.0/24")],
        )
        text = [str(n) for n in nets]
        # Remainder should not contain the holes, and should cover the rest.
        self.assertNotIn("10.0.1.0/24", text)
        collapsed = ck.summarize(nets + [ck.parse_network("10.0.1.0/24"), ck.parse_network("10.0.2.0/24")])
        self.assertEqual([str(n) for n in collapsed], ["10.0.0.0/16"])

    def test_exclude_ipv6(self):
        nets = ck.exclude(
            ck.parse_network("2001:db8::/32"),
            [ck.parse_network("2001:db8:1::/48")],
        )
        self.assertTrue(all(n.version == 6 for n in nets))
        self.assertFalse(any(n.overlaps(ck.parse_network("2001:db8:1::/48")) for n in nets))
        collapsed = ck.summarize(nets + [ck.parse_network("2001:db8:1::/48")])
        self.assertEqual([str(n) for n in collapsed], ["2001:db8::/32"])


class CliTests(unittest.TestCase):
    def run_main(self, argv, stdin_text=None):
        stdout = io.StringIO()
        stderr = io.StringIO()
        stdin = io.StringIO(stdin_text or "")
        with patch("sys.stdin", stdin), redirect_stdout(stdout), redirect_stderr(stderr):
            # isatty on StringIO is False, which is what we want for stdin summarize.
            code = ck.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_info_json(self):
        code, out, err = self.run_main(["--json", "info", "192.0.2.0/24"])
        self.assertEqual(code, 0, err)
        data = json.loads(out)
        self.assertEqual(data["usable_hosts"], 254)

    def test_contains_exit_codes(self):
        code, out, err = self.run_main(["contains", "10.0.0.0/8", "10.1.2.3"])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "yes")
        code, out, err = self.run_main(["contains", "10.0.0.0/8", "11.0.0.1"])
        self.assertEqual(code, 1)
        self.assertEqual(out.strip(), "no")

    def test_overlap_json(self):
        code, out, err = self.run_main(["--json", "overlap", "10.0.0.0/16", "10.1.0.0/16"])
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(out)["overlaps"])

    def test_summarize_stdin(self):
        code, out, err = self.run_main(
            ["summarize"],
            stdin_text="192.0.2.0/25\n# comment\n192.0.2.128/25\n",
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), "192.0.2.0/24")

    def test_bad_input_exit_2(self):
        code, out, err = self.run_main(["info", "not-an-ip"])
        self.assertEqual(code, 2)
        self.assertIn("cidr-kit:", err)
        self.assertEqual(out, "")


if __name__ == "__main__":
    unittest.main()
