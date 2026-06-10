import unittest
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw
import sniffer

class TestSnifferParser(unittest.TestCase):
    
    def setUp(self):
        # Reset stats before each test
        sniffer.reset_session()
        
    def test_get_packet_addresses_ipv4(self):
        pkt = Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/TCP()
        src, dst = sniffer.get_packet_addresses(pkt)
        self.assertEqual(src, "192.168.1.100")
        self.assertEqual(dst, "8.8.8.8")
        
    def test_get_packet_addresses_ipv6(self):
        pkt = Ether()/IPv6(src="fe80::1", dst="2001:db8::1")/UDP()
        src, dst = sniffer.get_packet_addresses(pkt)
        self.assertEqual(src, "fe80::1")
        self.assertEqual(dst, "2001:db8::1")
        
    def test_get_packet_addresses_arp(self):
        pkt = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")/ARP(psrc="192.168.1.1", pdst="192.168.1.254")
        src, dst = sniffer.get_packet_addresses(pkt)
        self.assertEqual(src, "192.168.1.1")
        self.assertEqual(dst, "192.168.1.254")
        
    def test_get_packet_protocol_dns(self):
        pkt = Ether()/IP()/UDP(sport=12345, dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
        self.assertEqual(sniffer.get_packet_protocol(pkt), "DNS")
        
    def test_get_packet_protocol_http_request(self):
        pkt = Ether()/IP()/TCP(sport=54321, dport=80)/Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertEqual(sniffer.get_packet_protocol(pkt), "HTTP")

    def test_get_packet_protocol_http_response(self):
        pkt = Ether()/IP()/TCP(sport=80, dport=54321)/Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
        self.assertEqual(sniffer.get_packet_protocol(pkt), "HTTP")
        
    def test_get_packet_protocol_tcp(self):
        pkt = Ether()/IP()/TCP(sport=12345, dport=443)
        self.assertEqual(sniffer.get_packet_protocol(pkt), "TCP")
        
    def test_get_packet_protocol_udp(self):
        pkt = Ether()/IP()/UDP(sport=12345, dport=5678)
        self.assertEqual(sniffer.get_packet_protocol(pkt), "UDP")
        
    def test_get_packet_protocol_icmp(self):
        pkt = Ether()/IP()/ICMP(type=8, code=0)
        self.assertEqual(sniffer.get_packet_protocol(pkt), "ICMP")
        
    def test_get_packet_protocol_arp(self):
        pkt = Ether()/ARP(op=1)
        self.assertEqual(sniffer.get_packet_protocol(pkt), "ARP")
        
    def test_update_stats(self):
        pkt_tcp = Ether()/IP()/TCP()
        pkt_udp = Ether()/IP()/UDP()
        pkt_dns = Ether()/IP()/UDP(dport=53)/DNS()
        pkt_icmp = Ether()/IP()/ICMP()
        pkt_arp = Ether()/ARP()
        
        sniffer.update_stats(pkt_tcp)
        sniffer.update_stats(pkt_udp)
        sniffer.update_stats(pkt_dns)
        sniffer.update_stats(pkt_icmp)
        sniffer.update_stats(pkt_arp)
        
        self.assertEqual(sniffer.stats["total"], 5)
        self.assertEqual(sniffer.stats["tcp"], 1)
        self.assertEqual(sniffer.stats["udp"], 2) # DNS counts as UDP + DNS
        self.assertEqual(sniffer.stats["dns"], 1)
        self.assertEqual(sniffer.stats["icmp"], 1)
        self.assertEqual(sniffer.stats["arp"], 1)

    def test_packet_matches_filter(self):
        pkt = Ether()/IP(src="192.168.1.15", dst="8.8.8.8")/TCP(sport=1234, dport=80)/Raw(load=b"GET / HTTP/1.1\r\n\r\n")
        
        # Test empty filter matches everything
        self.assertTrue(sniffer.packet_matches_filter(pkt, ""))
        
        # Test protocol filter
        self.assertTrue(sniffer.packet_matches_filter(pkt, "http"))
        self.assertFalse(sniffer.packet_matches_filter(pkt, "udp"))
        
        # Test IP filter
        self.assertTrue(sniffer.packet_matches_filter(pkt, "192.168.1.15"))
        self.assertTrue(sniffer.packet_matches_filter(pkt, "8.8.8.8"))
        self.assertFalse(sniffer.packet_matches_filter(pkt, "10.0.0.1"))
        
        # Test text filter in summary
        self.assertTrue(sniffer.packet_matches_filter(pkt, "GET"))
        self.assertFalse(sniffer.packet_matches_filter(pkt, "POST"))

if __name__ == "__main__":
    unittest.main()
