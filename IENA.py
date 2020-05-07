##Class to deconstruct IENA Header###

import struct
from collections import defaultdict
from collections import Counter
import math
import time

class IENA ():
        
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
        
    IENA_Format = '! 2s h H L 2x H'
    count = Counter()
    ttlbytes = 0
    timestamp = time.time() ## get the current time to determine the start of the sequence    

    def __init__(self):

        self.key = None 
        self.size = None
        self.timeHi= None
        self.timeLo= None
        self.sequence = None
        self.missedsequences = defaultdict(list)
        self.missedcount = 0
        self.missedtimes = []
        self.missedpacket = defaultdict(list)
        self.packetcounter = defaultdict(list)
        self.sequencewidth = 16
        self.packetnumber = 0
        self.packetcount = 0
        self.timer = []        

        self._packetStrut = struct.Struct(IENA.IENA_Format)

    def unpack(self,buf):

        self.key, self.size, self.timeHi, self.timeLo, self.sequence  = self._packetStrut.unpack_from(buf)

        previous_sequence = dict()
        ## Code to determine if the previous sequence and the current sequence have incremented by one ##
        if self.key not in previous_sequence :
                previous_sequence[self.key] = self.sequence
                self.packetcounter[self.key] = IENA.count ##Count the StreamIDs 
                #print ("Previous Sequence",IENA.count[self.key])
                for id in [self.key]:
                        IENA.count[id] += 1 ##Increment the counter, counter is used to detrmine the bitrate
                        #print("Counter",IENA.count) 
        elif((previous_sequence[self.key]+ 1) != self.sequence):
            if (previous_sequence[self.key]+ 1) == pow(2,self.sequencewidth) and self.sequence == 0: ## if the sequence is either 65535 or 0, do nothing as these values are rollovers (sequence runs from 0 to 65535)
               previous_sequence[self.streamid] = self.sequence
               #print(previous_sequence)
            else:
                self.missedsequences[self.key].append(previous_sequence[self.key]+1)
                self.missedcount += 1
                self.missedtimes.append(self.timeHi)
                self.missedpacket[self.packetnumber]=[previous_sequence[self.key]+1,self.sequence]
                previous_sequence[self.key] = self.sequence
                #print(previous_sequence)
        else:
            previous_sequence[self.streamid] = self.sequence
               
     ## Calculate the Bit rate for IENA ##       
    def bitRate(self):
        donestamp = time.time() 
        totalrcvs = 0
        ienadata = (self.size + 42) ## total packet size is IENA payload + previous headers
        #print("IENAdata",ienadata)
        IENA.ttlbytes = (ienadata * IENA.count[self.key])
        #print("ToalIENAbytes",IENA.ttlbytes)
        totalrcvs += 1
        totaltime = (donestamp - IENA.timestamp)
        #print("IENAtotaltime",totaltime)        
        rate = round((((IENA.ttlbytes * 8)/(donestamp - IENA.timestamp))/ 1000),3)    
        #print(rate)
        return rate
