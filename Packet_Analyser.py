import socket
import struct
import textwrap
import os

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, ipv4 source {}, ipv4 dest {} Protocol: {}'.format(dest_mac, src_mac,ipv4(src), ipv4(target), eth_proto))  

#Unpack the ethernet frame
def ethernet_frame(data):
        dest_mac,src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
        return get_mac_addr(dest_mac),get_mac_addr(src_mac), socket.htons(proto), data[:14]
 
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
    
main()        