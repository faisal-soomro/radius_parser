#!/usr/bin/python
#
#
# Importing the required libraries
# 
from scapy.all import Radius, sniff
from pyrad.packet import Packet
from pyrad.dictionary import Dictionary

count = 0
def parse_packet(packet):
    if(len(packet)>400 and packet.dport==1813):
        global count
        radius_packet=str(packet[Radius])
        pkt = Packet(packet=radius_packet, dict=Dictionary("dictionary"))
        attr1 =  pkt._DecodeKey(8)
        value1 = pkt.__getitem__(attr1)
        attr2 =  pkt._DecodeKey(31)
        value2 = pkt.__getitem__(attr2)
        count += 1
        print("%d Private IP: %s and MSISDN: %s" %(count,value1,value2))


sniff(iface='CAPTURE_INTERFACE', prn=parse_packet, filter="udp", store=0)
