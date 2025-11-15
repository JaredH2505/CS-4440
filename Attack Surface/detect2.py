#!/usr/bin/python3

# --------------------------------------------------------
# TODO: implement your attack/defense code in this file!
# --------------------------------------------------------

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from collections import namedtuple
import re

connections = {}
#First value in tuple is syn second sys acn
def parsePacket(packet):
    global  connections
    if not packet.haslayer("TCP"):
        return

    data = bytes(packet["TCP"].payload).decode('utf-8', 'replace')
    if connections.keys().__contains__(packet[IP].src) or connections.keys().__contains__(packet[IP].dst):
        #print("Prev IP")
        #print(packet.show())
        if packet[TCP].flags == "S":
            tup = list(connections[packet[IP].src]) # Convert to list to allow modifcation
            tup[0]+=1
            connections[packet[IP].src] = tuple(tup)
        elif packet[TCP].flags == "SA":
            tup = list(connections[packet[IP].dst])  # Convert to list to allow modifcation
            tup[1] += 1
            connections[packet[IP].dst] = tuple(tup)
    else:
        #print("New IP")
        connections[packet[IP].src] = (1,0)
        #packet.show()

    return


if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)
    for ip in connections.keys():
        if connections[ip][0] > connections[ip][1]*3:
            print(f"IP:{ip}, SYN:{connections[ip][0]}, SYNACK:{connections[ip][1]}")
    #print(connections)