#!/usr/bin/python3

# --------------------------------------------------------
# TODO: implement your attack/defense code in this file!
# --------------------------------------------------------

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re
import base64

dict = {}

def parsePacket(packet):
    global dict
    if not packet.haslayer("TCP"):
        return

    data = bytes(packet["TCP"].payload).decode('utf-8', 'replace')
    if data.startswith("GET"):
        raw = data.split("Authorization:")
        if raw[1] != "":
            raw = raw[1].split(" ")[2].replace("\r\n", "")
            user = base64.b64decode(raw).decode("ascii").split(":")
            dict[user[0]] = user[1]

    return


if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)
    for u in dict.keys():
        print(f"USERNAME:{u}, PASSWORD:{dict[u]}")
    #print(dict)