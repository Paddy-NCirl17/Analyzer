##Class to deconstruct UDP Header###

import struct

class UDP():
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

    UDP_Format = '! H H H 2x 4s'
    
    def __init__(self,buf=None):

        self.src_port = None
        self.dst_port = None
        self.len = None
        self.control = None # I put the INETX control within UDP construct to decifer between IENA and INETX

    def unpack(self,buf):
        (self.src_port,self.dst_port,self.len,self.control) = struct.unpack_from(UDP.UDP_Format,buf)
