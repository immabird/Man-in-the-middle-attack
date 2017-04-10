import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

while True:
    packet = s.recvfrom(65565)
    packet = packet[0]
    ip_header = packet[0:20]
    iph = unpack('!BBHHHBBH4s4s', ip_header)

    s_addr = socket.inet_ntoa(iph[8])
    if s_addr != '127.0.0.1':
        print(s_addr)
