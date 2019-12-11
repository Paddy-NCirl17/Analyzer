import socket
import struct
import textwrap
import os

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

# Reference: https://youtu.be/_HIefrog_eg

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))  

        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 17:
               src_port, dest_port, size, data = udp_packet(data)
               print(TAB_1 + 'UDP Packet:')
               print(TAB_2 + 'Source Port: {}, Destination Port: {}, Size: {}'.format(src_port, dest_port, size))

#Unpack the ethernet frame
def ethernet_frame(data):
        dest_mac,src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
        return get_mac_addr(dest_mac),get_mac_addr(src_mac), socket.htons(proto), data[14:]
 
 # formatting the MAC Address to AA:BB:CC:DD:EE:FF   
def get_mac_addr(bytes_addr):   
        bytes_str = map('{:02x}'.format, bytes_addr)
        return':'.join(bytes_str).upper()
        

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length =(version_header_length & 15) * 4
    ttl, proto, src, target, = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str,addr))
    
def udp_packet(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]
 
 
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])   
    
main()        