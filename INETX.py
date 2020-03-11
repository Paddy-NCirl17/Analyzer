##Class to deconstruct INETX Header###

import struct


class INETX ():
    DEF_CONTROL_WORD = 0x11000000
    INETX_HEADER_FORMAT = '>L4sLLQL'
    INETX_HEADER_LENGTH = struct.calcsize(INETX_HEADER_FORMAT)


    def __init__(self):
        self.inetxcontrol = INETX.DEF_CONTROL_WORD
        self.streamid = None
        self.sequence = None
        self.packetlen = None
        self.ptptime =None
        self.pif = None
        self.payload = None

        self._packetStrut = struct.Struct(INETX.INETX_HEADER_FORMAT)

    def unpack(self,buf):
        if len(buf) < INETX.INETX_HEADER_LENGTH:
            raise ValueError ("Buffer is too short to be an iNetX packet")

        self.inetxcontrol,self.streamid,self.sequence,self.packetlen,self.ptptime,self.pif = self._packetStrut.unpack_from(buf)

        if self.packetlen != len(buf):
            raise ValueError("Length of buffer 0x{:X} does not match length field 0x{:X}".format(len(buf),self.packetlen))

        self.payload = buf[INETX.INETX_HEADER_LENGTH:]
