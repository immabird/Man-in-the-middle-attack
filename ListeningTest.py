import socket, sys
from struct import *

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

while True:
    packet = s.recvfrom(65565)
    packet = packet[0]
    ip_header = packet[0:20]
    unpacked_iph = unpack('!BBHHHBBH4s4s', ip_header)

    ip_header_length = (unpacked_iph[0] & 0xF) * 4
    protocol = unpacked_iph[6]
    srcIP = socket.inet_ntoa(unpacked_iph[8])
    dstIP = socket.inet_ntoa(unpacked_iph[9])



    tcp_header = packet[ip_header_length:ip_header_length+20]
    unpacked_tcp = unpack('!HHLLBBHHH', tcp_header)

    srcPort = unpacked_tcp[0]
    dstPort = unpacked_tcp[1]
    unpacked_tcp_length = unpacked_tcp[4] >> 4

    header_size = ip_header_length + unpacked_tcp_length * 4

    data = packet[header_size:]

    if srcIP != '127.0.0.1':
        print('SrcIP: ' + str(srcIP) + ' SrcPort: ' + str(srcPort) + ' Data: ' + data)
