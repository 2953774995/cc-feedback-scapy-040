# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

"""
Pytest-native regression tests for the batch traffic triage module
(``scapy.audit``) and the integer payload stacking used by its probes.
"""

import time

from scapy.audit import triage_packets
from scapy.compat import raw
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

ITEM_KEYS = (
    "index", "ok", "reason", "l3", "l4", "src", "dst",
    "sport", "dport", "flow", "issues",
)


def build(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80,
          payload=b"", ttl=64, proto="tcp", frag=0, mf=0):
    pkt = Ether() / IP(src=src, dst=dst, ttl=ttl, flags=mf, frag=frag)
    if proto == "tcp":
        pkt = pkt / TCP(sport=sport, dport=dport) / payload
    elif proto == "udp":
        pkt = pkt / UDP(sport=sport, dport=dport) / payload
    return pkt


def test_basic_tcp_item_fields():
    out = triage_packets([build()])
    assert hasattr(out, "items") and hasattr(out, "stats")
    item = out.items[0]
    for key in ITEM_KEYS:
        assert key in item
    assert item["ok"] and item["reason"] == "ok"
    assert item["l3"] == "IPv4" and item["l4"] == "TCP"
    assert item["src"] == "10.0.0.1" and item["dst"] == "10.0.0.2"
    assert item["sport"] == 1234 and item["dport"] == 80
    assert item["index"] == 0 and item["issues"] == []


def test_icmp_and_ipv6():
    out = triage_packets([Ether() / ICMP() / b""])
    item = out.items[0]
    assert item["l4"] == "ICMP" and item["sport"] == 0 and item["dport"] == 0
    # ICMP carried without an IP layer is non-IP, like ARP.
    assert item["l3"] == "other" and item["reason"] == "non_ip"
    assert item["flow"] == ""

    # ICMP over IP still belongs to a flow (ports normalized to zero).
    ip_icmp = triage_packets([IP() / ICMP()]).items[0]
    assert ip_icmp["l4"] == "ICMP" and ip_icmp["flow"]

    v6 = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / 0
    out6 = triage_packets([v6])
    assert out6.items[0]["l3"] == "IPv6"
    assert "2001:db8::1" in str(out6.items[0]["src"])


def test_bidirectional_flow_merge():
    a = build(src="10.0.0.1", dst="10.0.0.2", sport=5000, dport=80)
    b = build(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=5000)
    out = triage_packets([a, b])
    assert out.items[0]["flow"] == out.items[1]["flow"]
    assert out.items[0]["flow"] == "10.0.0.1:5000<->10.0.0.2:80"
    assert out.stats["by_flow"][out.items[0]["flow"]] == 2


def test_fragment_offset_and_mf():
    assert triage_packets([build(frag=1480)]).items[0]["reason"] == "fragment"
    assert triage_packets([build(mf=1)]).items[0]["reason"] == "fragment"
    assert triage_packets([build()]).items[0]["reason"] == "ok"

    v6_frag = IPv6() / IPv6ExtHdrFragment(offset=1, m=1) / TCP()
    assert triage_packets([v6_frag]).items[0]["reason"] == "fragment"


def test_low_ttl():
    assert triage_packets([build(ttl=1)]).items[0]["reason"] == "ttl_low"
    assert triage_packets([build(ttl=64)]).items[0]["reason"] == "ok"


def test_cleartext_credentials():
    for payload in (b"USER anonymous\r\n", b"PASS secret\r\n",
                    b"Authorization: Basic Zm9vOg==\r\n"):
        item = triage_packets([build(proto="tcp", dport=21,
                                     payload=payload)]).items[0]
        assert item["reason"] == "cleartext_cred"
        assert "cleartext_cred" in item["issues"]

    plain_http = build(payload=b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
    assert triage_packets([plain_http]).items[0]["reason"] == "ok"


def test_port_policy_and_builtin_risky_ports():
    policy = {"allow_dports": [80, 443]}
    out = triage_packets([build(dport=80), build(dport=8080)], policy=policy)
    assert out.items[0]["reason"] == "ok"
    assert out.items[1]["reason"] == "port_denied"

    # Without a policy the built-in risky-port set still applies:
    # 5000 is flagged, an ordinary high port such as 8080 is not.
    assert triage_packets([build(dport=8080)]).items[0]["reason"] == "ok"
    risky = triage_packets([build(dport=5000)]).items[0]
    assert risky["reason"] == "port_denied" and not risky["ok"]


def test_arp_non_ip():
    item = triage_packets([ARP(psrc="10.0.0.1", pdst="10.0.0.2")]).items[0]
    assert item["l3"] == "ARP"
    assert item["reason"] == "non_ip" and not item["ok"]
    assert item["flow"] == ""


def test_malformed_objects_never_abort():
    out = triage_packets([None, "not a packet", 123, build()])
    assert [i["reason"] for i in out.items[:3]] == ["malformed"] * 3
    assert out.items[3]["reason"] == "ok"
    assert out.stats["bad"] == 3 and out.stats["ok"] == 1


def test_stats_and_empty_input():
    out = triage_packets([build(), build(dport=5000), b"not a packet"])
    stats = out.stats
    assert stats["ok"] == 1 and stats["bad"] == 2
    assert stats["by_l3"]["IPv4"] == 2
    assert stats["by_issue"]["port_denied"] == 1
    assert stats["by_issue"]["malformed"] == 1

    empty = triage_packets([])
    assert empty.items == []
    assert empty.stats == {
        "ok": 0, "bad": 0, "by_l3": {}, "by_issue": {}, "by_flow": {},
    }


def test_issue_priority():
    pkt = build(ttl=1, frag=100, dport=5000, payload=b"USER x\r\n")
    item = triage_packets([pkt]).items[0]
    assert item["reason"] == "fragment"
    assert set(item["issues"]) == {
        "fragment", "ttl_low", "cleartext_cred", "port_denied",
    }

    assert triage_packets(
        [build(ttl=1, payload=b"PASS x\r\n")]
    ).items[0]["reason"] == "ttl_low"


def test_generator_input_and_indexes():
    out = triage_packets(build() for _ in range(5))
    assert len(out.items) == 5
    assert [i["index"] for i in out.items] == list(range(5))


def test_udp_classification():
    item = triage_packets(
        [Ether() / IP() / UDP(sport=53, dport=53)]
    ).items[0]
    assert item["l3"] == "IPv4" and item["l4"] == "UDP"
    assert item["sport"] == 53 and item["dport"] == 53 and item["flow"]


def test_ten_thousand_packets_under_two_seconds():
    packets = [build()] * 10000
    start = time.perf_counter()
    out = triage_packets(packets)
    elapsed = time.perf_counter() - start
    assert len(out.items) == 10000
    assert elapsed < 2.0


def test_legacy_construction_api_unchanged():
    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=443)
    assert pkt[TCP].dport == 443 and pkt[IP].src == "1.1.1.1"


def test_integer_payload_stacks_as_raw():
    # ``pkt / 0`` must stack an empty Raw payload instead of raising.
    pkt = IP() / 0
    assert isinstance(pkt.payload, Raw)
    assert raw(pkt.payload) == b""

    five = IP() / 5
    assert raw(five.payload) == b"\x00" * 5
