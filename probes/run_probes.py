#!/usr/bin/env python3
"""验收探针：抓包流量批量分类与风险标注（10 条契约）。

全部离线：报文用 scapy 现场构造，不读 pcap 文件、不发包。
基线（未实现 `scapy.audit`）下 10 条应全部 FAIL。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RESULTS = []


def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn

    return deco


def triage():
    from scapy.audit import triage_packets

    return triage_packets


def build(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80, payload=b"", ttl=64,
          proto="tcp", frag=0, mf=0):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether

    pkt = Ether() / IP(src=src, dst=dst, ttl=ttl, flags=mf, frag=frag)
    if proto == "tcp":
        pkt = pkt / TCP(sport=sport, dport=dport) / payload
    elif proto == "udp":
        pkt = pkt / UDP(sport=sport, dport=dport) / payload
    return pkt


@probe("P01 批量入口与正常 TCP 报文")
def p01():
    fn = triage()
    out = fn([build()])
    assert hasattr(out, "items") and hasattr(out, "stats"), "需返回 items 与 stats"
    item = out.items[0]
    for key in ("index", "ok", "reason", "l3", "l4", "src", "dst", "sport", "dport", "flow", "issues"):
        assert key in item, f"item 缺字段 {key}"
    assert item["ok"] and item["reason"] == "ok", f"正常报文应 ok，实际 {item['reason']}"
    assert item["l3"] == "IPv4" and item["l4"] == "TCP", f"协议识别不对：{item['l3']}/{item['l4']}"
    assert item["src"] == "10.0.0.1" and item["dport"] == 80, "五元组取值不对"


@probe("P02 IPv6 与 ICMP 分类")
def p02():
    from scapy.layers.inet import ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether

    fn = triage()
    icmp = Ether() / ICMP() / b""
    out = fn([icmp])
    assert out.items[0]["l4"] == "ICMP", f"ICMP 应识别，实际 {out.items[0]['l4']}"
    assert out.items[0]["sport"] == 0 and out.items[0]["dport"] == 0, "ICMP 端口应为 0"

    v6 = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / 0
    out6 = fn([v6])
    assert out6.items[0]["l3"] == "IPv6", f"IPv6 应识别，实际 {out6.items[0]['l3']}"
    assert "2001:db8::1" in str(out6.items[0]["src"]), f"IPv6 源地址不对：{out6.items[0]['src']}"


@probe("P03 双向流量归并为同一 flow")
def p03():
    fn = triage()
    a = build(src="10.0.0.1", dst="10.0.0.2", sport=5000, dport=80)
    b = build(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=5000)
    out = fn([a, b])
    assert out.items[0]["flow"] == out.items[1]["flow"], \
        f"双向应同 flow，实际 {out.items[0]['flow']} vs {out.items[1]['flow']}"
    assert len(out.stats["by_flow"]) >= 1, "stats 应带 by_flow"


@probe("P04 分片标记")
def p04():
    fn = triage()
    out = fn([build()], )
    frag = build(frag=1480)
    out2 = fn([frag])
    assert out.items[0].get("reason") == "ok"
    assert out2.items[0]["reason"] == "fragment", f"偏移非零应记 fragment，实际 {out2.items[0]['reason']}"
    mf = build(mf=1)
    out3 = fn([mf])
    assert out3.items[0]["reason"] == "fragment", "MF 位置位也应记 fragment"


@probe("P05 TTL 过低告警")
def p05():
    fn = triage()
    out = fn([build(ttl=1)])
    assert out.items[0]["reason"] == "ttl_low", f"应为 ttl_low，实际 {out.items[0]['reason']}"
    out2 = fn([build(ttl=64)])
    assert out2.items[0]["reason"] == "ok", "正常 TTL 不应告警"


@probe("P06 明文凭据特征")
def p06():
    fn = triage()
    out = fn([build(proto="tcp", dport=21, payload=b"USER anonymous\r\nPASS x\r\n")])
    assert out.items[0]["reason"] == "cleartext_cred", f"应为 cleartext_cred，实际 {out.items[0]['reason']}"
    out2 = fn([build(payload=b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")])
    assert out2.items[0]["reason"] == "ok", "普通 HTTP 不应记为明文凭据"


@probe("P07 端口策略")
def p07():
    fn = triage()
    policy = {"allow_dports": [80, 443]}
    out = fn([build(dport=80), build(dport=8080)], policy=policy)
    assert out.items[0]["reason"] == "ok", "80 在白名单应 ok"
    assert out.items[1]["reason"] == "port_denied", f"8080 应记 port_denied，实际 {out.items[1]['reason']}"
    out3 = fn([build(dport=8080)])
    assert out3.items[0]["reason"] == "ok", "不传 policy 时不做端口判定"


@probe("P08 非 IP 报文")
def p08():
    from scapy.layers.l2 import ARP
    fn = triage()
    out = fn([ARP(psrc="10.0.0.1", pdst="10.0.0.2")])
    item = out.items[0]
    assert item["l3"] == "ARP", f"ARP 应记 l3=ARP，实际 {item['l3']}"
    assert item["reason"] == "non_ip" and not item["ok"], f"非 IP 应记 non_ip 且 ok 为假，实际 {item['reason']}"
    assert item["flow"] == "" or item["flow"] is None, "非 IP 不应产出 flow"


@probe("P09 统计口径与空输入")
def p09():
    fn = triage()
    out = fn([build(), build(dport=5000), b"not a packet"])
    st = out.stats
    assert st["ok"] == 1, f"ok 计数不对：{st}"
    assert st["bad"] == 2, f"bad 计数不对：{st}"
    assert st["by_l3"].get("IPv4") == 2, f"by_l3 不对：{st['by_l3']}"
    reasons = out.items[2]["reason"]
    assert reasons == "malformed", f"非报文对象应记 malformed，实际 {reasons}"
    empty = fn([])
    assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"


@probe("P10 万级性能与既有构造 API 不回归")
def p10():
    import time

    fn = triage()
    pkt = build()
    t0 = time.perf_counter()
    out = fn([pkt] * 10000)
    cost = time.perf_counter() - t0
    assert len(out.items) == 10000, "万条应全部产出 item"
    assert cost < 2.0, f"万条耗时 {cost:.2f}s 超过 2s"
    from scapy.layers.inet import IP, TCP

    q = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=443)
    assert q[TCP].dport == 443 and q[IP].src == "1.1.1.1", "既有构造 API 被破坏"


def main():
    print("=" * 60)
    print("验收探针：抓包流量批量分类与风险标注（10 条契约）")
    print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60)
    print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
