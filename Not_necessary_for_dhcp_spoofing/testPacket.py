#!/usr/bin/env python3
"""scapy-dhcp-listener.py
Listen for DHCP packets using scapy to learn when LAN
hosts request IP addresses from DHCP Servers.
Copyright (C) 2019 Shamiul Hasan
License MIT
"""

from __future__ import print_function

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

__version__ = "0.0.3"

def dhcp_offer(raw_mac, xid):
    packet = (Ether(src=get_if_hwaddr("wlo1"), dst='ff:ff:ff:ff:ff:ff') /
              IP(src="192.168.2.69", dst='255.255.255.255') /
              UDP(sport=67, dport=68) /
              BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr='192.168.2.4', siaddr='192.168.2.1', xid=xid) /
              DHCP(options=[("message-type", "offer"),
                            ('server_id', '192.168.2.1'),
                            ('subnet_mask', '255.255.255.0'),
                            ('router', '192.168.2.5'),
                            ('lease_time', 172800),
                            ('renewal_time', 86400),
                            ('rebinding_time', 138240),
                            "end"]))

    return packet


if __name__ == "__main__":
    pkt = dhcp_offer("ab:ab:ab:bc:cd:ab", 0x69696969)
    # print(pkt.command())
    print(pkt[Ether].src)
    # print(pkt[0].show())
