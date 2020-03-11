##Class to deconstruct UDP Header###

import struct

class UDP():
    '''Class to build and unpack a UDP packet'''
    UDP_HEADER_FORMAT = '>HHH2x4s'
    UDP_HEADER_SIZE = struct.calcsize(UDP_HEADER_FORMAT)
    def __init__(self,buf=None):

        self.srcport = None
        self.dstport = None
        self.len = None
        self.control = None
        self.payload = None

        if buf != None:
            self.unpack(buf)

    def unpack(self,buf):
        '''Unpack a buffer into a UDP object'''

        if len(buf) < UDP.UDP_HEADER_SIZE:
            raise ValueError("Buffer too short to be a UDP packet")
        (self.srcport,self.dstport,self.len,self.control) = struct.unpack_from(UDP.UDP_HEADER_FORMAT,buf)
        self.payload = buf[UDP.UDP_HEADER_SIZE:]
