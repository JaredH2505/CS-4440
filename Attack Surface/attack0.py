#!/usr/bin/python3

# --------------------------------------------------------
# TODO: implement your attack/defense code in this file!
# --------------------------------------------------------

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re

user =""
password = ""
type = ""


def findFTP(packet):
    global user
    global password
    global type
    if type == "":
        type = "FTP"
    data = bytes(packet["TCP"].payload).decode('utf-8', 'replace')
    if re.search("^PASS *", data):
        if password == "":
            password = data.split(" ")[1].replace("\r\n", "")
    if re.search("^USER *", data):
        if user == "":
            user = data.split(" ")[1].replace("\r\n", "")

    return


def findIMAP(packet):
    global user
    global password
    global type
    if type == "":
        type = "IMAP"
    data = bytes(packet["TCP"].payload).decode('utf-8', 'replace')
    if re.search("LOGIN", data):
        myList = data.split(" ")
        user = myList[2]
        password = myList[3].replace("\r\n", "")
    return


def parsePacket(packet):
    if not packet.haslayer("TCP"):
        return
    port = packet[TCP].sport
    if packet[TCP].dport == 21:
        findFTP(packet)
    elif packet[TCP].dport == 143:
        findIMAP(packet)

    return


if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)
    print(f"{type} USERNAME:{user}, PASSWORD:{password}")