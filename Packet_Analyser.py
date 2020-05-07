#!usr/bin/python3

import socket
import struct
import textwrap
import platform
import os
import sys
import json
import paho.mqtt.client as mqtt
from datetime import datetime
import time
import math
#import queue from Queue
import Ethernet as ethernet
import IP as ip
import UDP as udp
import INETX as inetx
import IENA as iena

<<<<<<< HEAD

broker_address="broker.mqttdashboard.com"
client = mqtt.Client("PADDY-IOT")
client.connect(broker_address)

 # formatting the MAC Address to AA:BB:CC:DD:EE:FF, for debug only 
=======
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
>>>>>>> b4f917a7a4539e987115dd94fb18d1b0e9225167
def get_mac_addr(bytes_addr):   
        bytes_str = map('{:02x}'.format, bytes_addr)
        return':'.join(bytes_str).upper()

## Covert to Hexadecimal##
def hexConvert(addr):
    str = map('{:02x}'.format,addr)
    return ''.join(str)
    
##convert IP addresses to readable format    
def ipv4(addr):
    return '.'.join(map(str,addr))        	     

##Convert PTPtime to readable format##    
def ptp(ptptime):
    seconds = (ptptime >> 32)
    nano_seconds = (ptptime & 0xffffffff)
    ptptime_hr = time.strftime("%a, %d %b %Y %H:%M:%S",time.localtime(seconds))
    return ptptime_hr

##Convert UnixTime to readable format##
def unix(timeHi, timeLo):
    startOfYear = datetime(datetime.today().year, 1,1,0,0,0,0)
    micro_seconds = timeLo +timeHi * 2**32
    doy = int(micro_seconds/1e6 + time.mktime(startOfYear.timetuple()))
    timestamp = time.strftime("%a, %d %b %Y %H:%M:%S",time.localtime(doy))
    return timestamp    
                    

def main():
   # RASP_IP = "192.168.0.10"
    #RASP_PORT = 5005
    totalbytes = 0
    timestamp = time.time()
    totaltime= 0
    totalrcvs = 0
    INETX = False

    operating_system = platform.system()
    print (operating_system)
    HOST = socket.gethostbyname(socket.gethostname())
    print (HOST)
    
##socket for windows skips the Ethernet layer.   
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
            #print('\nEthernet Frame:')
            #print('Destination: {}, Source: {}, Protocol: {}'.format(ethernet_header.dest_mac, ethernet_header.src_mac,ethernet_header.eth_proto)) 

            if ethernet_header.eth_proto == 8 or operating_system == 'Windows':
                ip_header = ip.IP()
                ip_header.unpack(raw_data[14:])
                #print('IPv4 Packet:')
                #print('Version: {}, Header Length: {}, TTL: {},'.format(ip_header.version, ip_header.len, ip_header.ttl))
                #print('Protocol: {}, Source: {}, Destination: {}'.format(ip_header.protocol, ipv4(ip_header.src_ip), ipv4(ip_header.dst_ip)))                

                if ip_header.protocol == 17 and ip_header.src_ip != '192.168.28.10':
                   udp_header = udp.UDP()
                   udp_header.unpack(raw_data[34:])
                   #print('UDP Packet:')
                   #print('Source Port: {}, Destination Port: {}, Size: {}, Control Field: {}'.format(udp_header.src_port, udp_header.dst_port, udp_header.len, hexConvert(udp_header.control)))                   
                   donestamp = time.time()
                   #print("donestamp",donestamp)
                   data = len(raw_data)
                   #print(data)
                   totalbytes += data
                   totalrcvs += 1
                   totaltime = round((donestamp - timestamp),0)
                   #print("totaltime",totaltime)
                   #print("totalrcvs",totalrcvs)
                   rate = round((((totalbytes* 8)/(donestamp - timestamp))/1000),3)
                   #print ("\nRcvd: %s bytes, %s total in %s s at %s kbps" % (data, totalbytes, donestamp - timestamp, rate))

                   if hexConvert(udp_header.control) == '11000000':
                       INETX = True
                       inetx_header = inetx.INETX()
                       inetx_header.unpack(raw_data[42:])
                       #print('iNET-X Packet:')
                       #print('Stream ID: {}, Sequence No: {}, iNET-X Length: {}, PTP TimeStamp: {}'.format(hexConvert(inetx_header.streamid), inetx_header.sequence, inetx_header.packetlen, ptp(inetx_header.ptptime) ))
 
                   elif hexConvert(udp_header.control) != '11000000':
                       iena_header = iena.IENA()
                       iena_header.unpack(raw_data[42:])          
            if INETX == True:        
                INETXpacket = {'type': 'INETX', 'id':hexConvert(inetx_header.streamid) , 'seq':inetx_header.sequence, 'src':ipv4(ip_header.src_ip),'dst':ipv4(ip_header.dst_ip),'size':udp_header.len,'time':ptp(inetx_header.ptptime),'drop':inetx_header.missedcount,'BR':inetx_header.bitRate(),}                     
                packet_json = json.dumps(INETXpacket)
                ttlBitrate = json.dumps({'ttlBR':rate,})
                client.publish("Packet", packet_json)
                client.publish("ttlBitrate",ttlBitrate)
            else:
                IENApacket = {'type': 'IENA', 'id':hexConvert(iena_header.key) , 'seq':iena_header.sequence, 'src':ipv4(ip_header.src_ip),'dst':ipv4(ip_header.dst_ip),'size':udp_header.len,'time':unix(iena_header.timeHi,iena_header.timeLo),'drop':iena_header.missedcount,'BR':iena_header.bitRate(),}                     
                packet_json = json.dumps(IENApacket)
                ttlBitrate = json.dumps({'ttlBR':rate,})
                client.publish("Packet", packet_json)
                client.publish("ttlBitrate",ttlBitrate)                    
main()
 
