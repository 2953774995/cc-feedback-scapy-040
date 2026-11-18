# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Philippe Biondi <phil@secdev.org>

"""
Batch traffic triage for SOC packet auditing.

``triage_packets`` classifies a batch of Scapy packets by L3/L4 protocol,
extracts five-tuples, merges both directions of a conversation into a single
flow key and flags risk conditions (fragments, low TTL, cleartext
credentials, unauthorized destination ports) without touching the protocol
implementations under ``scapy.layers``.
"""

from collections import namedtuple

from scapy.compat import raw
from scapy.error import log_runtime
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.l2 import ARP
from scapy.packet import Packet

__all__ = ["TriageResult", "triage_packets"]

#: Substrings that reveal credentials sent in cleartext over TCP.
AUDIT_CLEARTEXT_MARKERS = (b"USER ", b"PASS ", b"Authorization: Basic")

#: Destination ports considered unauthorized unless the caller supplies an
#: explicit ``allow_dports`` policy (remote access, databases, common
#: trojan/backdoor and admin services).
AUDIT_RISKY_DPORTS = frozenset(
    [
        23,  # telnet
        135,  # MSRPC
        137,  # NetBIOS
        138,  # NetBIOS
        139,  # NetBIOS session
        445,  # SMB
        1433,  # MSSQL
        1521,  # Oracle
        2049,  # NFS
        2375,  # Docker daemon (unencrypted)
        3306,  # MySQL
        3389,  # RDP
        5000,  # UPnP / commplex
        5432,  # PostgreSQL
        5900,  # VNC
        5985,  # WinRM
        6379,  # Redis
        8086,  # InfluxDB
        9200,  # Elasticsearch
        11211,  # memcached
        27017,  # MongoDB
    ]
)

#: Risk conditions, ordered from highest to lowest priority. The first match
#: becomes the item's ``reason``; every match still ends up in ``issues``.
AUDIT_PRIORITY = (
    "non_ip",
    "fragment",
    "ttl_low",
    "cleartext_cred",
    "port_denied",
    "malformed",
)

TriageResult = namedtuple("TriageResult", ["items", "stats"])


def _audit_flow_key(src, sport, dst, dport):
    """Normalize a five-tuple into an unordered, direction-independent key."""
    left = (src, sport)
    right = (dst, dport)
    if left <= right:
        return "%s:%d<->%s:%d" % (src, sport, dst, dport)
    return "%s:%d<->%s:%d" % (dst, dport, src, sport)


def _audit_ip_item(pkt, l3_name, src, dst, ttl, frag_off, more_frag,
                   allow_dports):
    """Classify an IP/IPv6 packet once its L3 fields have been extracted."""
    item = {
        "index": 0,
        "ok": False,
        "reason": "ok",
        "l3": l3_name,
        "l4": "-",
        "src": src,
        "dst": dst,
        "sport": 0,
        "dport": 0,
        "flow": "",
        "issues": [],
    }
    issues = item["issues"]

    if frag_off or more_frag:
        issues.append("fragment")
    if ttl is not None and ttl <= 1:
        issues.append("ttl_low")

    tcp_layer = pkt.getlayer(TCP)
    udp_layer = pkt.getlayer(UDP)
    icmp_layer = pkt.getlayer(ICMP)
    if tcp_layer is not None:
        l4_layer = tcp_layer
        item["l4"] = "TCP"
    elif udp_layer is not None:
        l4_layer = udp_layer
        item["l4"] = "UDP"
    elif icmp_layer is not None:
        l4_layer = None
        item["l4"] = "ICMP"
    else:
        l4_layer = None

    if l4_layer is not None:
        item["sport"] = l4_layer.sport
        item["dport"] = l4_layer.dport

    item["flow"] = _audit_flow_key(
        item["src"], item["sport"], item["dst"], item["dport"]
    )

    if tcp_layer is not None:
        payload = raw(tcp_layer.payload)
        if any(marker in payload for marker in AUDIT_CLEARTEXT_MARKERS):
            issues.append("cleartext_cred")

    if l4_layer is not None:
        if allow_dports is not None:
            if item["dport"] not in allow_dports:
                issues.append("port_denied")
        elif item["dport"] in AUDIT_RISKY_DPORTS:
            issues.append("port_denied")

    return item


def _audit_one(pkt, allow_dports):
    """Classify a single object into a triage item."""
    if not isinstance(pkt, Packet):
        return {
            "index": 0,
            "ok": False,
            "reason": "malformed",
            "l3": "other",
            "l4": "-",
            "src": "",
            "dst": "",
            "sport": 0,
            "dport": 0,
            "flow": "",
            "issues": ["malformed"],
        }

    arp_layer = pkt.getlayer(ARP)
    ip_layer = pkt.getlayer(IP)
    v6_layer = pkt.getlayer(IPv6)

    if arp_layer is not None and ip_layer is None and v6_layer is None:
        return {
            "index": 0,
            "ok": False,
            "reason": "non_ip",
            "l3": "ARP",
            "l4": "-",
            "src": arp_layer.psrc,
            "dst": arp_layer.pdst,
            "sport": 0,
            "dport": 0,
            "flow": "",
            "issues": ["non_ip"],
        }

    if ip_layer is not None:
        item = _audit_ip_item(
            pkt,
            "IPv4",
            ip_layer.src,
            ip_layer.dst,
            ip_layer.ttl,
            ip_layer.frag,
            bool(ip_layer.flags.MF),
            allow_dports,
        )
    elif v6_layer is not None:
        v6_frag = pkt.getlayer(IPv6ExtHdrFragment)
        if v6_frag is not None:
            frag_off = v6_frag.offset
            more_frag = bool(v6_frag.m)
        else:
            frag_off = 0
            more_frag = False
        item = _audit_ip_item(
            pkt,
            "IPv6",
            v6_layer.src,
            v6_layer.dst,
            v6_layer.hlim,
            frag_off,
            more_frag,
            allow_dports,
        )
    else:
        l4 = "-"
        if pkt.getlayer(ICMP) is not None:
            l4 = "ICMP"
        item = {
            "index": 0,
            "ok": False,
            "reason": "non_ip",
            "l3": "other",
            "l4": l4,
            "src": "",
            "dst": "",
            "sport": 0,
            "dport": 0,
            "flow": "",
            "issues": ["non_ip"],
        }

    if item["issues"]:
        for reason in AUDIT_PRIORITY:
            if reason in item["issues"]:
                item["reason"] = reason
                break
        item["ok"] = False
    else:
        item["reason"] = "ok"
        item["ok"] = True
    return item


def triage_packets(packets, policy=None):
    """Classify a batch of packets and aggregate flow-level statistics.

    :param packets: iterable of Scapy packets. Objects that are not packets
        are reported with ``reason='malformed'`` instead of aborting the
        batch.
    :param policy: optional mapping; when it carries ``allow_dports`` the
        destination port of TCP/UDP packets must belong to that whitelist or
        the packet is flagged ``port_denied``. Without a policy, only a
        built-in set of high-risk destination ports is flagged.
    :returns: a :class:`TriageResult` of per-packet items and statistics.
    """
    allow_dports = None
    if policy is not None:
        allow_dports = set(policy.get("allow_dports", []))

    items = []
    ok_count = 0
    bad_count = 0
    by_l3 = {}
    by_issue = {}
    by_flow = {}

    for index, pkt in enumerate(packets):
        try:
            item = _audit_one(pkt, allow_dports)
        except Exception as exc:
            # A single weird object must never interrupt the whole batch.
            log_runtime.debug("triage_packets: item %d failed: %s", index, exc)
            item = {
                "index": index,
                "ok": False,
                "reason": "malformed",
                "l3": "other",
                "l4": "-",
                "src": "",
                "dst": "",
                "sport": 0,
                "dport": 0,
                "flow": "",
                "issues": ["malformed"],
            }
        item["index"] = index
        items.append(item)

        if item["ok"]:
            ok_count += 1
        else:
            bad_count += 1
        by_l3[item["l3"]] = by_l3.get(item["l3"], 0) + 1
        for issue in item["issues"]:
            by_issue[issue] = by_issue.get(issue, 0) + 1
        if item["flow"]:
            by_flow[item["flow"]] = by_flow.get(item["flow"], 0) + 1

    stats = {
        "ok": ok_count,
        "bad": bad_count,
        "by_l3": by_l3,
        "by_issue": by_issue,
        "by_flow": by_flow,
    }
    return TriageResult(items, stats)
