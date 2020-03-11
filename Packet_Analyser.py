import socket
import struct
import textwrap
import platform
import os
from datetime import datetime
import time
#import queue from Queue
import Ethernet as ethernet
import IP as ip
import UDP as udp
import INETX as inetx
import IENA as iena

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '
 
 # formatting the MAC Address to AA:BB:CC:DD:EE:FF   
def get_mac_addr(bytes_addr):   
        bytes_str = map('{:02x}'.format, bytes_addr)
        return':'.join(bytes_str).upper()

def hexConvert(addr):
    str = map('{:02x}'.format,addr)
    return ''.join(str)	     
    
def ptp(ptptime):
    seconds = (ptptime >> 32)
    nano_seconds = (ptptime & 0xffffffff)
    ptptime_hr = time.strftime("%a, %d %b %Y %H:%M:%S",time.localtime(seconds))
    nano_format = ('{:09d}'.format(nano_seconds))
    ptptime_conv = ptptime_hr+'.'+nano_format
    return ptptime_conv

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
            ethernet_header = ethernet.Ethernet()
            ethernet_header.unpack(raw_data)
            print('\nEthernet Frame:')
            print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(get_mac_addr(ethernet_header.dest_mac), get_mac_addr(ethernet_header.src_mac), socket.htons(ethernet_header.eth_proto)))  

            if socket.htons(ethernet_header.eth_proto) == 8 or operating_system == 'Windows':
                ip_header = ip.IP()
                ip_header.unpack(raw_data[14:])
                print(TAB_1 + 'IPv4 Packet:')
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ip_header.version, ip_header.ihl, ip_header.ttl))
                print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ip_header.protocol, ip_header.srcip, ip_header.dstip))

                if ip_header.protocol == 17:
                   udp_header = udp.UDP()
                   udp_header.unpack(raw_data[34:])
                   print(TAB_1 + 'UDP Packet:')
                   print(TAB_2 + 'Source Port: {}, Destination Port: {}, Size: {}, Control Field: {}'.format(udp_header.srcport, udp_header.dstport, udp_header.len, hexConvert(udp_header.control)))

                   if hexConvert(udp_header.control) == '11000000':
                       inetx_header = inetx.INETX()
                       inetx_header.unpack(raw_data[42:])
                       print(TAB_1 + 'iNET-X Packet:')
                       print(TAB_2 + 'Stream ID: {}, Sequence No: {}, iNET-X Length: {}, PTP TimeStamp: {}'.format(hexConvert(inetx_header.streamid), inetx_header.sequence, inetx_header.packetlen, ptp(inetx_header.ptptime) ))

                   elif hexConvert(udp_header.control) != '11000000':
                       iena_header = iena.IENA()
                       iena_header.unpack(raw_data[42:])
                       print(TAB_1 + 'IENA Packet:')
                       print(TAB_2 + 'IENA Key: {},Size: {}, Sequence No: {},Time: {} '.format( iena_header.key, iena_header.size,  iena_header.sequence,  unix(iena_header.timestamp)))
	 
main()
