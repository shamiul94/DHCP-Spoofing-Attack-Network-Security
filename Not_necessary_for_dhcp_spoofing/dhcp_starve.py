from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


def dhcp_discover(dst_mac="ff:ff:ff:ff:ff:ff"):
    src_mac = get_if_hwaddr(conf.iface)
    spoofed_mac = '40:b8:9a:a1:e7:f5'
    options = [("message-type", "discover"),
               ("max_dhcp_size", 1500),
               ("client_id", mac2str(spoofed_mac)),
               ("lease_time", 10000),
               ("end", "0")]
    transaction_id = random.randint(1, 900000000)
    discover = Ether(src=src_mac, dst=dst_mac) \
               / IP(src="0.0.0.0", dst="255.255.255.255") \
               / UDP(sport=68, dport=67) \
               / BOOTP(chaddr=[spoofed_mac],  # mac2str(spoofed_mac)
                       xid=transaction_id,
                       flags=0xFFFFFF) \
               / DHCP(options=options)
    sendp(discover,
          iface=conf.iface)


if __name__ == "__main__":
    while True:
        dhcp_discover()
