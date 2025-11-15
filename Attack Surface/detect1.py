#!/usr/bin/python3

# --------------------------------------------------------
# TODO: implement your attack/defense code in this file!
# --------------------------------------------------------

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re

NullSource = ""
NullCount =0
FinSource = ""
FinCount =0
XmasSource = ""
XmasCount = 0

def parsePacket(packet):
    global NullSource
    global NullCount
    global FinSource
    global FinCount
    global XmasSource
    global XmasCount

    if not packet.haslayer("TCP"):
        return

    data = bytes(packet["TCP"].payload).decode('utf-8', 'replace')
    #print(packet.show())
    #print(f"flags: {packet[TCP].flags}")
    if packet[TCP].flags == "":
        #print("Null packet")
        #print(packet.show())
        NullCount+=1
        if NullSource =="":
            NullSource = packet[IP].src
    if packet[TCP].flags == "F":
        FinCount+=1
        if FinSource == "":
            FinSource = packet[IP].src
    if packet[TCP].flags == "FPU":
        XmasCount+=1
        if  XmasSource == "":
            XmasSource = packet[IP].src


    return


if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)
    print(f"NULLScan, IP:{NullSource}, COUNT:{NullCount}")
    print(f"FINScan, IP:{FinSource}, COUNT:{FinCount}")
    print(f"XMASScan, IP:{XmasSource}, COUNT:{XmasCount}")
