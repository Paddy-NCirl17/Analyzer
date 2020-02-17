import socket
import struct
import textwrap
import platform
import os
from datetime import datetime
import time

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


def main():
   # RASP_IP = "192.168.0.10"
    #RASP_PORT = 5005
    operating_system = platform.system()
    print (operating_system)
    HOST = socket.gethostbyname(socket.gethostname())
    print (HOST)
    
    if operating_system == 'Windows':
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((HOST, 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.ntohs(3))
        conn.bind(('eth0', 0))	
        
    while True:
        if operating_system == 'Linux':
            raw_data, addr = conn.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))  

            if eth_proto == 8 or operating_system == 'Windows':
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                print(TAB_1 + 'IPv4 Packet:')
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(version, header_length, ttl))
                print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

                if proto == 17:
                   src_port, dest_port, size, control_field,udp_data = udp_packet(data)
                   print(TAB_1 + 'UDP Packet:')
                   print(TAB_2 + 'Source Port: {}, Destination Port: {}, Size: {}, Control Field: {}'.format(src_port, dest_port, size, control_field))

                   if control_field == '11000000':
                       stream_id, seq_no, inet_length, ptp_time, data = inetx_packet(udp_data)
                       print(TAB_1 + 'iNET-X Packet:')
                       print(TAB_2 + 'Stream ID: {}, Sequence No: {}, iNET-X Length: {}, PTP TimeStamp: {}'.format(stream_id, seq_no, inet_length, ptp_time ))

                   elif control_field != '11000000':
                         key, size, timestamp, seq, data= iena_packet(data)
                         print(TAB_1 + 'IENA Packet:')
                         print(TAB_2 + 'IENA Key: {},Size: {}, Sequence No: {},Time: {} '.format(key, size, seq, timestamp))
	 
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
    src_port, dest_port, size, control_field = struct.unpack('! H H H 2x 4s', data[:12])
    return src_port, dest_port, size, inet(control_field), data[12:]
    
def inet(addr):
    str = map('{:02x}'.format,addr)
    return ''.join(str)

def inetx_packet(data):
    stream_id, seq_no, inet_length, ptp_time  = struct.unpack('! 4s l 4s Q', data[:20])
    return inet(stream_id), seq_no,inet(inet_length),ptp(ptp_time), data[20:]

def iena_packet(udp_data):
    key, size, timestamp, seq = struct.unpack('! 8x 2s 2s Q h', udp_data[:22])
    return inet(key), inet(size), unix(timestamp), seq, udp_data[22:]	     
    
def ptp(ptp_time):
    seconds = (ptp_time >> 32)
    nano_seconds = (ptp_time & 0xffffffff)
    ptp_time_hr = time.strftime("%a, %d %b %Y %H:%M:%S",time.localtime(seconds))
    nano_format = ('{:09d}'.format(nano_seconds))
    ptp_time_conv = ptp_time_hr+'.'+nano_format
    return ptp_time_conv

def unix(timestamp):
    seconds = (timestamp >> 32)
    micro_seconds = (timestamp & 0xffff)
    time_hr = time.strftime("%a, %d %b %Y %H:%M:%S",time.localtime(seconds))
    micro_format = ('{:04d}'.format(micro_seconds))
    time_conv = time_hr+'.'+ micro_format
    return time_conv

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])   
    
main()
