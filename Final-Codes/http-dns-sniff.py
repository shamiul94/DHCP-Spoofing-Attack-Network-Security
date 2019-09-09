from scapy.all import *
from scapy.layers.inet import IP


def packet_handler(packet):

    if packet[IP].src == '192.168.0.76':
        print(packet.show())
    print('###################################')


if __name__ == "__main__":
    sniff(iface="wlo1", filter="udp and (port 53 or 80)", prn=packet_handler)
