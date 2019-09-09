from scapy.all import *
from scapy.layers.inet import IP


def packet_handler(packet):
    print('------------ command ---------------')
    # print(packet.command())
    print('************* show **************')

    if packet[IP].src == '192.168.0.69':
        print(packet.show())
    print('###################################')


if __name__ == "__main__":
    # sniff(iface="wlo1",filter="udp and (port 67 or 68)", prn=packet_handler)
    # ,filter="udp and (port 53)"
    sniff(iface="wlo1", filter="udp and (port 53 or 80)", prn=packet_handler)
