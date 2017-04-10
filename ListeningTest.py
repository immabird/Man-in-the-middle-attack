#!/usr/bin/env python
import struct
import socket
import binascii

rawSocket=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.htons(0x0800))
#ifconfig eth0 promisc up
rawSocket.bind(('',443))
receivedPacket=rawSocket.recvfrom(2048)

#Ethernet Header...
ethernetHeader=receivedPacket[0:14]
ethrheader=struct.unpack("!6s6s2s",ethernetHeader)
destinationIP= binascii.hexlify(ethrheader[0])
sourceIP= binascii.hexlify(ethrheader[1])
protocol= binascii.hexlify(ethrheader[2])
print("Destinatiom: " + destinationIP)
print("Souce: " + sourceIP)
print("Protocol: "+ protocol)

#IP Header...
ipHeader=receivedPacket[0][14:34]
ipHdr=struct.unpack("!12s4s4s",ipHeader)
destinationIP=socket.inet_ntoa(ipHdr[2])
print("Source IP: " +sourceIP)
print("Destination IP: "+destinationIP)

#TCP Header...
tcpHeader=receivedPacket[0][34:54]
tcpHdr=struct.unpack("!2s2s16s",tcpHeader)
sourcePort=socket.inet_ntoa(tcpHdr[0])
destinationPort=socket.inet_ntoa(tcpHdr[1])
print("Source Port: " + sourcePort)
print("Destination Port: " + destinationPort)
