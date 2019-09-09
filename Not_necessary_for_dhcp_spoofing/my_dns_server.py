#! /usr/bin/env python3

from __future__ import print_function

from scapy.all import *
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP

dns_req = (IP(dst="8.8.8.8") /
           UDP(sport=RandShort(), dport=53) /
           DNS(rd=1, qd=DNSQR(qname="www.lightoj.com", qtype="A")))


def packet_handler(packet):
    fake_dns_reply = IP(src='8.8.8.8', dst='192.168.0.69') / \
                     UDP(sport=53, dport=22243, len=71, chksum=19295) / \
                     DNS(length=None, id=0, qr=1, opcode=0, aa=0, tc=0, rd=1,
                         ra=1, z=0, ad=0, cd=0, rcode=0, qdcount=1, ancount=2,
                         nscount=0, arcount=0, qd=DNSQR(qname=b'www.lightoj.com.', qtype=1, qclass=1),
                         an=DNSRR(rrname=b'www.lightoj.com.', type=5, rclass=1, ttl=21599, rdata=b'lightoj.com.') / \
                            DNSRR(rrname=b'lightoj.com.', type=1, rclass=1, ttl=21599, rdata='108.161.128.53'),
                         ns=None, ar=None)


if __name__ == "__main__":
    # sniff(filter='udp port 53', iface='wlo1', prn=lambda x: x.show())
    print(RandShort())
