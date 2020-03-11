##Class to deconstruct Ethernet Header###

import struct

class Ethernet():

    ETHERNET_HEADER_FORMAT = '! 6s 6s H'
    ETHERNET_HEADER_LENGTH = struct.calcsize(ETHERNET_HEADER_FORMAT)
    
    def __init__(self):
        self.dest_mac = None
        self.src_mac = None
        self.eth_proto = None

        self._packetStrut = struct.Struct(Ethernet.ETHERNET_HEADER_FORMAT)

    def unpack(self, buf):
        if len(buf) < Ethernet.ETHERNET_HEADER_LENGTH:
            raise ValueError("Buffer is too short to be an ETHERNET packet")

        self.dest_mac, self.src_mac, self.eth_proto = self._packetStrut.unpack_from(buf)

        self.payload = buf[Ethernet.ETHERNET_HEADER_LENGTH: ]
