import socket, sys
from struct import *

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

        if srcIP == Host_One_IP or srcIP == Host_Two_IP:
            print('SrcIP: ' + str(srcIP) + ' DestPort: ' + str(dstPort) + ' Data: ' + str(data))

listen_to_incoming_packets('127.0.0.1', '127.0.0.1')
