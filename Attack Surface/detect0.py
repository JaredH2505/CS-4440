#!/usr/bin/python3

# --------------------------------------------------------
# TODO: implement your attack/defense code in this file!
# --------------------------------------------------------

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re

sourceIP = ""
destIP = ""
numReqest = 0
numFails = 0

def parsePacket(packet):
    global sourceIP
    global destIP
    global numReqest
    global numFails
    if not packet.haslayer("TCP"):
        return

    data = bytes(packet["TCP"].payload).decode('utf-8', 'replace')
    if re.search("^PASS *",data):
        if sourceIP == "":
            sourceIP = packet[IP].src
            destIP = packet[IP].dst
        numReqest+=1
    if re.search("^530",data):
        if packet[IP].src == destIP:
            numFails+=1


if __name__ == "__main__":
    sourceIP = ""
    destIP = ""
    numReqest = 0
    numFails = 0
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)
    out = "IP:{ip}, REQS:{r}, FAILS:{f}".format(ip=sourceIP,r=numReqest,f=numFails)
    print(out)
