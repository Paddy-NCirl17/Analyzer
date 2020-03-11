##Class to deconstruct IP Header###

import struct
import socket

class IP():
    PROTOCOLS = {"ICMP":0x01,"IGMP" : 0X02, "TCP":0x6,"UDP":0x11}
    IP_HEADER_FORMAT = '>BBHHBBBBHII'
    IP_HEADER_SIZE = struct.calcsize(IP_HEADER_FORMAT)

    def __init__(self,buf=None):
        self.srcip = None
        self.dstip = None
        self.len = None
        self.flags = 0x0
        self.protocol = IP.PROTOCOLS['UDP'] # default to udp
        self.payload = None
        self.version = 4 # IPV4
        self.ihl = 5 # Header len in 32 bit words
        self.dscp = 0
        self.id = 0
        self.ttl = 20

        if buf != None:
            self.unpack(buf)

    def unpack(self,buf):
        '''Unpack a buffer into an ethernet object'''

        if len(buf) < IP.IP_HEADER_SIZE:
            raise ValueError("Buffer too short for to be an IP packet")
        (na1,self.dscp, self.len,self.id,self.flags,na3, self.ttl, self.protocol, checksum, self.srcip,self.dstip) = struct.unpack_from(IP.IP_HEADER_FORMAT,buf)
        self.flags = self.flags >> 5
        self.srcip = socket.inet_ntoa(struct.pack('!I',self.srcip))
        self.dstip = socket.inet_ntoa(struct.pack('!I',self.dstip))
        self.payload = buf[IP.IP_HEADER_SIZE:]

