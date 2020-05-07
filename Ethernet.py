##Class to deconstruct Ethernet Header###

import struct
import socket

class Ethernet():
    
    ##http://docs.python.org/2/library/struct.html
##Format    C Type          Python type         Standard size   Notes
##  x       pad             byte                no value
##  c       char            string of length 1      1
##  b       signed char     integer                 1 (3)
##  B       unsigned char   integer                 1 (3)
##  ?       _Bool           bool                    1 (1)
##  h       short           integer                 2 (3)
##  H       unsigned short  integer                 2 (3)
##  i       int             integer                 4 (3)
##  I       unsigned int    integer                 4 (3)
##  l       long            integer                 4 (3)
##  L       unsigned        long integer            4 (3)
##  q       long            long integer            8 (2), (3)
##  Q       unsigned long   long integer            8 (2), (3)
##  f       float           float                   4 (4)
##  d       double          float                   8 (4)
##  s       char[]          string
##  p       char[]          string
##  P       void *          integer   (5), (3)  

    Ethernet_Format = '! 6s 6s H'
    
    def __init__(self):
        self.dest_mac = None
        self.src_mac = None
        self.eth_proto = None

        self._packetStrut = struct.Struct(Ethernet.Ethernet_Format)

    def unpack(self, buf):
        self.dest_mac, self.src_mac, self.eth_proto = self._packetStrut.unpack_from(buf)
        self.eth_proto = socket.htons(self.eth_proto)
