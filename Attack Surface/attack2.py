#!/usr/bin/python3

# --------------------------------------------------------
# TODO: implement your attack/defense code in this file!
# --------------------------------------------------------

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
# This came from my research into if scrapy has built in functionaly for HTTP requests
# Source: https://www.thepythoncode.com/article/sniff-http-packets-scapy-python
from scapy.layers.http import HTTPRequest
import re

results = []

def parsePacket(packet):
    global results
    if not packet.haslayer("TCP"):
        return

    if packet.haslayer(HTTPRequest):
        host = packet[HTTPRequest].Host.decode()
        request = packet[HTTPRequest].Path.decode()
        results.append(host + request)
    data = bytes(packet["TCP"].payload).decode('utf-8', 'replace')
    #if data.startswith("GET"):
    #    print(packet.layers())


    return


if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)
    for r in results:
        print(f"URL:{r}")