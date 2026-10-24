import os
import tempfile
import pytest
from scapy.all import Ether, IP, TCP
from backend.sniffer import LiveSniffer, get_interfaces

def test_get_interfaces_structure():
    ifaces = get_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    for iface in ifaces:
        assert "id" in iface
        assert "name" in iface
        assert "status" in iface

def test_live_sniffer_buffer_and_pcap():
    captured = []
    def callback(pkt):
        captured.append(pkt)

    sniffer = LiveSniffer(callback)
    assert not sniffer.is_running
    assert len(sniffer.captured_packets) == 0

    # Simulate packet reception
    sample_pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=80, dport=8080)
    sniffer._handle_packet(sample_pkt)

    assert len(captured) == 1
    assert len(sniffer.captured_packets) == 1

    # Test PCAP file export
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        success = sniffer.save_pcap(tmp_path)
        assert success is True
        assert os.path.exists(tmp_path)
        assert os.path.getsize(tmp_path) > 0
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    # Test clear
    sniffer.clear()
    assert len(sniffer.captured_packets) == 0
