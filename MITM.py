import socket
from struct import pack
from uuid import getnode as get_mac

class arp():

    def __init__(self):
        arp.packet = [
            pack('!H', 0x0001),#2 bytes
            pack('!H', 0x0800),#2 bytes
            pack('!B', 0x06),#1 byte
            pack('!B', 0x04),#1 byte
            pack('!H', 0x0002),#2 bytes (2 = arp reply)
            pack('!6B', 0x34, 0x97, 0xF6, 0x38, 0x13, 0x47),#6 bytes (Sender mac address)
            pack('!4B', 0x34, 0x97, 0xF6, 0x38),#4 bytes (Sender ip address)
            pack('!6B', 0x34, 0x97, 0xF6, 0x38, 0x13, 0x47),#6 bytes (Target mac address)
            pack('!4B', 0x34, 0x97, 0xF6, 0x38),#4 bytes (Target ip address)
        ]
        print(arp.packet)

    def reply(self, ip = 'localhost'):

        s = socket.socket(AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
        s.bind(("en1", 0))
        s.send(arp.packet)

a = arp()
a.reply()
