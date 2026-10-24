import time
import base64
import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
from backend.analyzer import PacketAnalyzer

@pytest.fixture
def analyzer():
    return PacketAnalyzer()

def test_initial_state(analyzer):
    stats = analyzer.get_stats()
    assert stats["total_packets"] == 0
    assert stats["total_bytes"] == 0
    assert stats["bytes_sec"] == 0.0
    assert stats["packets_sec"] == 0.0
    assert stats["alerts_count"] == 0
    assert analyzer.protocol_counts["TCP"] == 0
    assert analyzer.protocol_counts["UDP"] == 0
    assert analyzer.protocol_counts["ARP"] == 0
    assert analyzer.protocol_counts["DNS"] == 0
    assert analyzer.protocol_counts["ICMP"] == 0

def test_ipv4_tcp_packet(analyzer):
    pkt = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
          IP(src="192.168.1.100", dst="10.0.0.1", ttl=64) / \
          TCP(sport=12345, dport=80, flags="S", seq=1000) / \
          Raw(load=b"Hello Apex")
    
    parsed = analyzer.process_packet(pkt)
    assert parsed["protocol"] == "TCP"
    assert parsed["source"] == "192.168.1.100"
    assert parsed["destination"] == "10.0.0.1"
    assert "IPv4" in parsed["layers"]
    assert parsed["layers"]["IPv4"]["TTL"] == 64
    assert "TCP" in parsed["layers"]
    assert parsed["layers"]["TCP"]["Source Port"] == 12345
    assert parsed["layers"]["TCP"]["Destination Port"] == 80
    assert "S" in parsed["layers"]["TCP"]["Flags"]
    assert parsed["payload"] is not None
    # Verify base64 payload decoding
    decoded = base64.b64decode(parsed["payload"])
    assert decoded == b"Hello Apex"
    assert analyzer.protocol_counts["TCP"] == 1

def test_ipv6_udp_packet(analyzer):
    pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=5000, dport=6000) / Raw(load=b"TestUDP")
    parsed = analyzer.process_packet(pkt)
    assert parsed["protocol"] == "UDP"
    assert parsed["source"] == "2001:db8::1"
    assert parsed["destination"] == "2001:db8::2"
    assert "IPv6" in parsed["layers"]
    assert "UDP" in parsed["layers"]
    assert parsed["layers"]["UDP"]["Source Port"] == 5000
    assert analyzer.protocol_counts["UDP"] == 1

def test_icmp_packet(analyzer):
    pkt = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / ICMP(type=8, code=0)
    parsed = analyzer.process_packet(pkt)
    assert parsed["protocol"] == "ICMP"
    assert "ICMP" in parsed["layers"]
    assert parsed["layers"]["ICMP"]["Type"] == 8
    assert analyzer.protocol_counts["ICMP"] == 1

def test_arp_packet_and_spoofing(analyzer):
    # Legitimate ARP reply
    arp_pkt1 = Ether(src="aa:bb:cc:dd:ee:01") / ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01", pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
    analyzer.process_packet(arp_pkt1)
    assert analyzer.arp_table["192.168.1.1"] == "aa:bb:cc:dd:ee:01"
    assert len(analyzer.alerts) == 0

    # Conflicting ARP reply from attacker
    arp_pkt2 = Ether(src="66:66:66:66:66:66") / ARP(op=2, psrc="192.168.1.1", hwsrc="66:66:66:66:66:66", pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
    analyzer.process_packet(arp_pkt2)
    assert len(analyzer.alerts) >= 1
    alert = analyzer.alerts[-1]
    assert alert["category"] == "ARP Spoofing Detected"
    assert alert["severity"] == "Critical"
    assert "IP Conflict" in alert["message"]

def test_dns_normal_and_tunneling(analyzer):
    # Normal DNS query
    dns_normal = Ether() / IP(src="192.168.1.20", dst="8.8.8.8") / UDP(sport=53000, dport=53) / \
                 DNS(rd=1, qd=DNSQR(qname="google.com"))
    parsed = analyzer.process_packet(dns_normal)
    assert parsed["protocol"] == "DNS"
    assert analyzer.protocol_counts["DNS"] == 1
    assert len(analyzer.alerts) == 0

    # Suspicious DNS Tunneling (length > 80)
    long_domain = "a" * 85 + ".example.com"
    dns_tunnel = Ether() / IP(src="192.168.1.20", dst="8.8.8.8") / UDP(sport=53001, dport=53) / \
                 DNS(rd=1, qd=DNSQR(qname=long_domain))
    analyzer.process_packet(dns_tunnel)
    assert any(a["category"] == "Suspicious DNS Tunneling" for a in analyzer.alerts)

    # Suspicious domain TLD (.xyz)
    dns_malicious = Ether() / IP(src="192.168.1.20", dst="8.8.8.8") / UDP(sport=53002, dport=53) / \
                    DNS(rd=1, qd=DNSQR(qname="bad-c2-server.xyz"))
    analyzer.process_packet(dns_malicious)
    assert any(a["category"] == "Suspicious Domain Requested" for a in analyzer.alerts)

def test_port_scan_detection(analyzer):
    src_ip = "192.168.1.77"
    # Send packets to 16 unique destination ports
    for port in range(1, 18):
        pkt = Ether() / IP(src=src_ip, dst="192.168.1.10") / TCP(sport=40000 + port, dport=port, flags="S")
        analyzer.process_packet(pkt)
    
    assert any(a["category"] == "Port Scanning Detected" for a in analyzer.alerts)

def test_syn_flood_detection(analyzer):
    src_ip = "10.10.10.99"
    # Send 55 SYN packets to trigger threshold (>50)
    for _ in range(55):
        pkt = Ether() / IP(src=src_ip, dst="10.10.10.1") / TCP(sport=50000, dport=443, flags="S")
        analyzer.process_packet(pkt)
    
    assert any(a["category"] == "SYN Flood Anomaly" for a in analyzer.alerts)

def test_large_data_transfer_alert(analyzer):
    # Payload > 1400 bytes
    large_payload = b"X" * 1450
    pkt = Ether() / IP(src="192.168.1.5", dst="192.168.1.6") / TCP(sport=8080, dport=9000, flags="PA") / Raw(load=large_payload)
    analyzer.process_packet(pkt)
    assert any(a["category"] == "Large Data Transfer" for a in analyzer.alerts)

def test_http_detection(analyzer):
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = Ether() / IP(src="192.168.1.5", dst="93.184.216.34") / TCP(sport=45000, dport=80, flags="PA") / Raw(load=http_payload)
    parsed = analyzer.process_packet(pkt)
    assert parsed["protocol"] == "HTTP"
    assert "HTTP: GET /index.html HTTP/1.1" in parsed["info"]
