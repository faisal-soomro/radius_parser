#!/usr/bin/python
#
#
# Importing the required libraries
# 
from scapy.all import PcapReader, Radius
from pyrad.packet import Packet
from pyrad.dictionary import Dictionary
from time import time
#
#
# Reading the traffic capture with scapy rdpcap module - stores packets as a list
#
#
count = 0
totaltime = 0
start_parse = time()
end_parse = time()
def parse_packet(filename):
    with PcapReader(filename) as file_capture:
        global start_parse, end_parse, count, totaltime
        for packet in file_capture:
            try:
                if(len(packet)>400 and packet.dport==1813): # We only need pcakets whose length is greater than 400 bytes
                    # Capturing the RAW data from packet (the index value for raw data is 3)
                    start_parse = time()
                    radius_packet=str(packet[Radius])                     
                    # Pyrad has a dictionary with the RADIUS attributes defined, It'll help in decoding the RAW Packet
                    pkt = Packet(packet=radius_packet, dict=Dictionary("dictionary"))
                    attr1 =  pkt._DecodeKey(8)
                    value1 = pkt.__getitem__(attr1)
                    attr2 =  pkt._DecodeKey(31)
                    value2 = pkt.__getitem__(attr2)
                    end_parse = time()
                    print("Time Taken to parse RADIUS packet: %s seconds" %(end_parse-start_parse))
                    count += 1
                    totaltime += (end_parse-start_parse)
                    print("%d Private IP: %s and MSISDN: %s" %(count,value1,value2)) 
            except AttributeError:
                print("Port attribute not available in the packet, skipping the parsing on the packet... ")

start_func = time()
parse_packet('PCAP_FILE_FULL_PATH')
stop_func = time()

print("Time Elapsed: %s seconds" %(stop_func-start_func))
print("Average Packet Parsing Time: %s seconds" %(totaltime/count))
