import socket
import os
import struct
from ctypes import *
import threading
import time
from netaddr import IPNetwork, IPAddress

host = "192.168.1.101"
subnet = "192.168.0.0/24"
magic_message = "PYTHONRULES"

class IP(Structure):
    _fields_ = [
        ("ip_head_length", c_ubyte, 4),
        ("ip_version", c_ubyte, 4),
        ("ip_tos", c_ubyte),
        ("ip_len", c_ushort),
        ("ip_id", c_ushort),
        ("ip_offset", c_ushort),
        ("ip_ttl", c_ubyte),
        ("ip_protocol", c_ubyte),
        ("ip_sum", c_ushort),
        ("ip_src", c_ulong),
        ("ip_dst", c_ulong)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.ip_src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.ip_dst))

        try:
            self.protocol = self.protocol_map[self.ip_protocol]
        except:
            self.protocol = str(self.ip_protocol)


class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("unused", c_ushort),
        ("next_hop_mtu", c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass


if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

def udp_sender(subnet, magic_message):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ip in IPNetwork(subnet):
        try:
            sender.sendto(magic_message, ("%s" % ip, 65212))
        except:
            pass


t = threading.Thread(target=udp_sender, args=(subnet, magic_message))
t.start()


try:
    while True:
        raw_buffer = sniffer.recvfrom(65535)[0]
        ip_header = IP(raw_buffer[0:20])
        #print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
        if ip_header.protocol == "ICMP":
            offset = ip_header.ip_head_length * 4
            buf = raw_buffer[offset:offset + sizeof(ICMP)]
            icmp_header = ICMP(buf)
            #print("ICMP -> Type: %d Code: %d" % (icmp_header.type, icmp_header.code))
            if icmp_header.code == 3 and icmp_header.type == 3:
                if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                    if raw_buffer[len(raw_buffer) - len(magic_message):] == magic_message:
                        print("Host up: %s" % ip_header.src_address)
except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)