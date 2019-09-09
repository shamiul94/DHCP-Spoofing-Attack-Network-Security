from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


def make_test_discover_packet():
    src_mac = get_if_hwaddr(conf.iface)
    my_mac = '40:b8:9a:a1:e7:f5'  # might have to be changed for other networks
    spoofed_mac = my_mac
    options = [("message-type", "discover"),
               ("max_dhcp_size", 1500),
               ("client_id", mac2str(spoofed_mac)),
               ("lease_time", 10000),
               ("end", "0")]
    transaction_id = random.randint(1, 900000000)
    test_discover_packet = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") \
                           / IP(src="0.0.0.0", dst="255.255.255.255") \
                           / UDP(sport=68, dport=67) \
                           / BOOTP(chaddr=[spoofed_mac],  # mac2str(spoofed_mac)
                                   xid=transaction_id,
                                   flags=0xFFFFFF) \
                           / DHCP(options=options)
    return test_discover_packet


def counter_measure():
    test_discover_packet = make_test_discover_packet()
    sendp(test_discover_packet, iface="wlo1")


if __name__ == "__main__":
    counter_measure()
