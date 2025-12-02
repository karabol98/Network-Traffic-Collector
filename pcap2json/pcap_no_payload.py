#!/usr/bin/env python3
from scapy.utils import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.ntp import NTP
from scapy.layers.ssh import SSH
from scapy.layers.tftp import TFTP
from scapy.layers.dhcp import DHCP
from scapy.layers.dhcp6 import DHCP6
from scapy.layers.l2 import ARP
import sys

INFILE = sys.argv[1]
OUTFILE = sys.argv[2]

packets = rdpcap(INFILE)
new_packets = []
count = 0
parts = 1

from multiprocessing import Pool

for packet in packets:
    if packet.haslayer("IP"):
        if packet.haslayer("TCP"):
            packet["IP"]["TCP"].remove_payload()
        elif packet.haslayer("UDP"):
            packet["IP"]["UDP"].remove_payload()
        if packet.haslayer("DNS"):
            packet["IP"]["DNS"].remove_payload()
        elif packet.haslayer("HTTP"):
            packet["IP"]["HTTP"].remove_payload()
        elif packet.haslayer("NTP"):
            packet["IP"]["NTP"].remove_payload()
        elif packet.haslayer("SSH"):
            packet["IP"]["SSH"].remove_payload()
        elif packet.haslayer("TFTP"):
            packet["IP"]["TFTP"].remove_payload()
        elif packet.haslayer("DHCP"):
            packet["IP"]["DHCP"].remove_payload()


    if packet.haslayer("IPv6"):
        if packet.haslayer("TCP"):
            packet["IPv6"]["TCP"].remove_payload()
        elif packet.haslayer("UDP"):
            packet["IPv6"]["UDP"].remove_payload()

        if packet.haslayer("DNS"):
            packet["IPv6"]["DNS"].remove_payload()
        elif packet.haslayer("HTTP"):
            packet["IPv6"]["HTTP"].remove_payload()
        elif packet.haslayer("NTP"):
            packet["IPv6"]["NTP"].remove_payload()
        elif packet.haslayer("SSH"):
            packet["IPv6"]["SSH"].remove_payload()
        elif packet.haslayer("DHCP6"):
            packet["IP"]["DHCP6"].remove_payload()

    if packet.haslayer(ARP):
        # For ARP packets, we anonymize the addresses
        arp_layer = packet.getlayer(ARP)
        arp_layer.pdst = "0.0.0.0"
        arp_layer.psrc = "0.0.0.0"
        arp_layer.hwdst = "00:00:00:00:00:00"
        arp_layer.hwsrc = "00:00:00:00:00:00"

    if packet.haslayer("ICMP"):
        packet["ICMP"].remove_payload()
    if packet.haslayer("ICMPv6"):
        packet["ICMPv6"].remove_payload()

wrpcap(OUTFILE, packets)
