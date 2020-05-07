##Class to deconstruct IP Header###

import struct
import socket

class IP():
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

    IP_Format = '! 2x H 4x B B 2x 4s 4s'

    def __init__(self,buf=None):
        self.src_ip = None
        self.dst_ip = None
        self.len = None
        self.protocol = 0x11 #UDP is 0x11
        self.version = 4 #IPV4 is 4
        self.ttl = 20 # Time to Live

    def unpack(self,buf):

        (self.len, self.ttl, self.protocol,self.src_ip,self.dst_ip) = struct.unpack_from(IP.IP_Format,buf)
