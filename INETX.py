##Class to deconstruct INETX Header###

import struct
from collections import defaultdict
from collections import Counter
import math
import time



class INETX ():
        
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
        
    INETX_Format = '! 4x 4s L L Q 4x'
    count = Counter()
    ttlbytes = 0
    timestamp = time.time() ## get the current time to determine the start of the sequence


    def __init__(self):
        self.streamid = None
        self.sequence = None
        self.packetlen = None
        self.ptptime =None
        self.missedsequences = defaultdict(list)
        self.missedcount = 0
        self.missedtimes = []
        self.missedpacket = defaultdict(list)
        self.packetcounter = defaultdict(list)
        self.sequencewidth = 32
        self.packetnumber = 0
        self.packetcount = 0
        self.timer = []


        self._packetStrut = struct.Struct(INETX.INETX_Format)

    def unpack(self,buf):

        self.streamid,self.sequence,self.packetlen,self.ptptime = self._packetStrut.unpack_from(buf)
        self.timer.append(self.ptptime)
        
        previous_sequence = dict()
        ## Code to determine if the previous sequence and the current sequence have incremented by one ##
        if self.streamid not in previous_sequence :
                previous_sequence[self.streamid] = self.sequence
                self.packetcounter[self.streamid] = INETX.count ##Count the StreamIDs 
                #print ("Previous Sequence",INETX.count[self.streamid])
                for id in [self.streamid]:
                        INETX.count[id] += 1 ##Increment the counter, counter is used to detrmine the bitrate
                        #print("Counter",INETX.count) 
        elif((previous_sequence[self.streamid]+ 1) != self.sequence):
            if (previous_sequence[self.streamid]+ 1) == pow(2,self.sequencewidth) and self.sequence == 0: ## if the sequence is either 2^32 or 0, do nothing as these values are rollovers (sequence runs from 0 to 2^32)
               previous_sequence[self.streamid] = self.sequence
               #print(previous_sequence)
            else:
                self.missedsequences[self.streamid].append(previous_sequence[self.streamid]+1)
                self.missedcount += 1
                self.missedtimes.append(self.ptptime)
                self.missedpacket[self.packetnumber]=[previous_sequence[self.streamid]+1,self.sequence]
                previous_sequence[self.streamid] = self.sequence
                #print(previous_sequence)
        else:
            previous_sequence[self.streamid] = self.sequence
               
     ## Calculate the Bit rate for INETX ##       
    def bitRate(self):
        donestamp = time.time() 
        totalrcvs = 0
        inetxdata = (self.packetlen + 42) ## total packet size is INETx payload + previous headers
        #print("INETXdata",inetxdata )
        INETX.ttlbytes = (inetxdata * INETX.count[self.streamid])
        #print("ToalINETXbytes",INETX.ttlbytes)
        totalrcvs += 1
        totaltime = (donestamp - INETX.timestamp)
        #print("INETXtotaltime",totaltime)        
        rate = round((((INETX.ttlbytes * 8)/(donestamp - INETX.timestamp))/ 1000),3)    
        #print(rate)
        return rate
