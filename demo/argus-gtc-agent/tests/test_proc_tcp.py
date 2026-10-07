from __future__ import annotations

import unittest

from argus_gtc_agent.proc_tcp import parse_proc_net_tcp


class ProcTcpTests(unittest.TestCase):
    def test_parses_established_ipv4_source_tuple(self):
        # 10.131.0.15:41001 -> 172.30.185.74:31999 ESTABLISHED
        table = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
            "retrnsmt   uid  timeout inode\n"
            "   0: 0F00830A:A029 4AB91EAC:7CFF 01 00000000:00000000 00:00000000 "
            "00000000     0        0 12345 1 0000000000000000 20 4 30 10 -1\n"
        )
        source_ip, source_port = parse_proc_net_tcp(table, "172.30.185.74", 31999)
        self.assertEqual(source_ip, "10.131.0.15")
        self.assertEqual(source_port, 41001)

    def test_ignores_unrelated_destinations(self):
        table = (
            "  sl  local_address rem_address   st\n"
            "   0: 0F00830A:A019 4AB91EAC:0050 01\n"
        )
        source_ip, source_port = parse_proc_net_tcp(table, "172.30.185.74", 31999)
        self.assertIsNone(source_ip)
        self.assertIsNone(source_port)


if __name__ == "__main__":
    unittest.main()
