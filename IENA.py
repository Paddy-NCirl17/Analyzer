##Class to deconstruct IENA Header###

import struct

class IENA ():
    IENA_HEADER_FORMAT = '>HHHIBBH'
    IENA_HEADER_LENGTH = struct.calcsize(IENA_HEADER_FORMAT)
    TRAILER_LENGTH = 2

    def __init__(self):

        self.key = None 
        self.size = None
        self.timestamp= None
        self.keystatus = None
        self.status = None
        self.sequence = None
        self.endfield = 0xdead
        self.payload = None #string containing payload

        self._packetStrut = struct.Struct(IENA.IENA_HEADER_FORMAT)

    def unpack(self,buf):
        if len(buf) < IENA.IENA_HEADER_LENGTH:
            raise ValueError("Buffer passed to unpack is too small to be an IENA packet")

        (self.key, self.size, self.timestamp, self.keystatus, self.status, self.sequence)  = self._packetStrut.unpack_from(buf)

        self.payload = buf[IENA.IENA_HEADER_LENGTH:-2]
        (self.endfield,) = struct.unpack(">H",buf[-2:]) # last two bytes are the trailer
