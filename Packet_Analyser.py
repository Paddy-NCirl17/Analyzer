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


broker_address="broker.mqttdashboard.com"
client = mqtt.Client("PADDY-IOT")
client.connect(broker_address)

 # formatting the MAC Address to AA:BB:CC:DD:EE:FF, for debug only 
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
    
    ## Define Variables ###
    totalbytes = 0 
    timestamp = time.time()
    totaltime= 0
    totalrcvs = 0
    INETX = False 
## Find the current Host of the Analyzer ###
    operating_system = platform.system()
    HOST = socket.gethostbyname(socket.gethostname())
    
## Windows and Linux(Raspberry Pi) Bind differently to a Socket ###
    if operating_system == 'Windows':
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((HOST, 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.ntohs(3))
        conn.bind(('eth0', 0))	

##        
    while True:
        if operating_system == 'Linux':
            raw_data, addr = conn.recvfrom(65535)
            ethernet_header = ethernet.Ethernet()
            ethernet_header.unpack(raw_data)
            
##socket for windows skips the Ethernet layer as this is not a requirement. ###  
            if ethernet_header.eth_proto == 8 or operating_system == 'Windows':
                ip_header = ip.IP()
                ip_header.unpack(raw_data[14:])               

                if ip_header.protocol == 17 and ip_header.src_ip != '192.168.28.10':
                   udp_header = udp.UDP()
                   udp_header.unpack(raw_data[34:])                  
                   donestamp = time.time()
                   data = len(raw_data)
                   totalbytes += data
                   totalrcvs += 1
                   totaltime = round((donestamp - timestamp),0)
                   rate = round((((totalbytes* 8)/(donestamp - timestamp))/1000),3)

                   if hexConvert(udp_header.control) == '11000000':
                       INETX = True
                       inetx_header = inetx.INETX()
                       inetx_header.unpack(raw_data[42:])
 
                   elif hexConvert(udp_header.control) != '11000000':
                       iena_header = iena.IENA()
                       iena_header.unpack(raw_data[42:]) 
 ## publish contents of headers to MQTT ##                               
            if INETX == True:        
                INETXpacket = {'type': 'INETX', 'id':hexConvert(inetx_header.streamid) , 'seq':inetx_header.sequence, 'src':ipv4(ip_header.src_ip),'dst':ipv4(ip_header.dst_ip),'size':udp_header.len,'time':ptp(inetx_header.ptptime),'BR':inetx_header.bitRate(),}                     
                packet_json = json.dumps(INETXpacket)
                ttl = json.dumps({'ttlBR':rate,'pktNo': totalrcvs,'drop':inetx_header.missedcount,})
                client.publish("Packet", packet_json)
                client.publish("ttl",ttl)
            else:
                IENApacket = {'type': 'IENA', 'id':hexConvert(iena_header.key) , 'seq':iena_header.sequence, 'src':ipv4(ip_header.src_ip),'dst':ipv4(ip_header.dst_ip),'size':udp_header.len,'time':unix(iena_header.timeHi,iena_header.timeLo),'BR':iena_header.bitRate(),}                     
                packet_json = json.dumps(IENApacket)
                ttl = json.dumps({'ttlBR':rate,'pktNo': totalrcvs,'drop':iena_header.missedcount,})
                client.publish("Packet", packet_json)
                client.publish("ttl",ttl)                    
main()
 
