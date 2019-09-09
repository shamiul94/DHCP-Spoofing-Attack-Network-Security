from scapy.all import *
from scapy.layers.dhcp import DHCP

offer_count = 0


def packet_handler(packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 2:
        global offer_count
        offer_count = offer_count + 1
        print("Offer packet #" + str(offer_count))
        print(packet.summary())
        if offer_count > 1:
            print("XXXX" + str(offer_count) + " DHCP Servers found in the network. Attacks might happen." + "XXXX")
            exit(1)


# print('************* show **************')

if __name__ == "__main__":
    sniff(iface="wlo1", filter="udp and (port 67 or 68)", prn=packet_handler)
