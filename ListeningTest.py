import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

while True:
    packet = s.recvfrom(65565)
    print packet[1]
    packet = packet[0]
    ip_header = packet[0:20]
    unpacked_iph = unpack('!BBHHHBBH4s4s', ip_header)

    ip_header_length = (version_ihl & 0xF) * 4
    protocol = unpacked_iph[6]
    srcIP = socket.inet_ntoa(unpacked_iph[8])
    dstIP = socket.inet_ntoa(unpacked_iph[9])



    tcp_header = packet[ip_header_length:ip_header_length+20]
    unpacked_tcp = unpack('!HHLLBBHHH', tcp_header)

    srcPort = tcph[0]
    dstPort = tcph[1]
    tcph_length = tcph[4] >> 4

    header_size = ip_header_length + tcph_length * 4

    data = packet[header_size:]

    print('SrcIP: ' + str(srcIP) + 'DestPort: ' + str(dstPort) + 'Data: ' + data)
