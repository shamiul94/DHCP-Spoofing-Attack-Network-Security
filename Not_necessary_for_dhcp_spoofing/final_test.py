#! /usr/bin/env python3

from __future__ import print_function

from scapy.all import *
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import IP, UDP

dns_req = (IP(dst="8.8.8.8") /
           UDP(sport=1555, dport=53) /
           DNS(rd=1, qd=DNSQR(qname="www.lightoj.com", qtype="A")))

ans = sr1(dns_req)

# fake_dns_reply = 

print('-----------------my query-----------------')
print(dns_req.show())
print()
print(dns_req.command())

print('------------------routers\' reply-------------------')
print(ans.show())
print()
print(ans.command())
print()
print(ans.an[1].rdata)

# print(ans[DNS].summary())
