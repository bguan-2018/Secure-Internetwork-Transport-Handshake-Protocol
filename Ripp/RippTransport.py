from .RippPacket import RippPacket
import random
import time
import hashlib
import playground.network.common as common
import math
import threading
import asyncio

def createRecvTimer(trans):
    return threading.Timer(0, trans.tryBuffer)

def createSendTimer(trans,load,idx):
    return threading.Timer(.1,trans.trySend,args=[load,idx])

def createFinTimer(trans):
    return threading.Timer(10,trans.send_fin)

def createSynTimer(trans):
    return threading.Timer(2,trans.send_syn)

class BadPacketError(Exception):
    pass

# THE TRANSPORT IS THE SAME LAYER AS THE PROTOCOL
class RippTransport(common.StackingTransport):
    def __init__(self, lowerTransport, protocol):
        super().__init__(lowerTransport)
        self.protocol = protocol
        self.state = "LISTEN" #maybe should be LISTEN, was initially CLOSED
        self.seq = self._generate_seq()
        self.prevAck = 0
        self.pktsProcessed=0
        self.packetBuffer = []  
        self.windowSize = 16
        self.count = 0
        self.timer = createRecvTimer(self)
        self.sendStack=[]
        self.dataToSend=[]
        self.loop = asyncio.get_event_loop()
        self.sendStackCond = threading.Lock()
        self.prevAckCond = threading.RLock()
        self.seqCond = threading.Lock()
        self.pktBufferCond = threading.Lock()
        self.synTimer = None
        self.synCounter = 0
        self.finTimer = None
        self.finCounter = 0
        
    def get_protocol(self):
        return self.protocol
    @staticmethod
    def _has_load(packet):
        if "DATA" in packet.Type: 
            return True
        return False

    def connect(self):
#         print(str(self._extra['peername'][1]) + ": " + "Connecting!")
        self.send_syn()

    def bind(self):
        #not sure I need this
        self.state = "LISTEN"

    @staticmethod
    def _generate_seq():
        return random.randint(0, 100000)

    def _send(self, Type = "", load=None, setSeq=None):
        with self.seqCond and self.prevAckCond:
            packet = RippPacket();
            if setSeq:
                packet.SeqNo = setSeq;
            else:
                packet.SeqNo = self.seq;
            packet.AckNo = self.prevAck
            packet.Type = Type
#             print(str(self._extra['peername'][1]) + ": " + "Sending packet type: " + packet.Type)

            ##NEED TO DO CHECKSUM STUFF
            packet.CRC = b''
            if load:
                packet.Data = load
            else:
                packet.Data = b''
            ser1 = packet.__serialize__()
            m = hashlib.sha256()
            m.update(ser1)
            packet.CRC = m.digest()
            if not self.state == "CLOSED":
                self._lowerTransport.write(packet.__serialize__())
    
    def send_syn(self):
        if self.synCounter < 4:
#             print(str(self._extra['peername'][1]) + ": " + "sending Syn")
            self.state = "SYN-SENT"
            self._send(Type="SYN")
            self.synCounter +=1
            if self.synTimer:
                self.synTimer.cancel()
            self.synTimer = createSynTimer(self)
            self.synTimer.start()
        else:
            self._close()

    def _send_ack(self, Type = "", load=None):
        if not "ACK" in Type:
            Type +="ACK" 
        
        self._send(Type, load=load)
        
    def send_fin(self):
#         print("tryna send fin")
#         for el in self.sendStack:
#             el[0].cancel()
        if (self.finCounter < 4):
            self._send(Type="FIN")
            self.finCounter+=1
            self.finTimer = createFinTimer(self)
            self.finTimer.start()
        #timeout
        else:
            self._close()
        
    def _send_data(self, seq, Type = "", load=None,idx=0):
        if not "DATA" in Type:
            Type +="DATA" 
        self._send(Type, load=load,setSeq=seq)
    
    def stillHaveStuffToSend(self):
        #Run this twice JUST to check
#         if(len(self.sendStack) == 0):
#             print("length of sendstack is 0")
        for el in self.sendStack:
            if el[0].is_alive():
                return True
        for el in self.sendStack:
            if el[0].is_alive():
                return True
#         print("have no stuff to send")
        return False
        
        
    def send_finack(self):
        #make sure everything is wrapped up
#         print("waiting for buffers")
        while(len(self.packetBuffer) > 1 and not self.stillHaveStuffToSend()):
#             print(str(self._extra['peername'][1]) + ": " + "pktbuflen: " + str(len(self.packetBuffer)) + " sendStackLen: " + str(len(self.sendStack)))
            time.sleep(1)
        #send fin
#         print("should send finack now")
        self._send_ack(Type="FIN")
        self._close()
    
    
    
    def close(self):
        #make sure everything is wrapped up
        print("Close called")
        while(len(self.packetBuffer) > 1 and not self.stillHaveStuffToSend()):
#             print("sleeping til empty" + str(len(self.packetBuffer)))
            time.sleep(1)
        self.state="FIN-SENT"
        self.send_fin()
#         print("FIN SENT")
#         for el in self.sendStack:
#             el[0].cancel()
#         self._close()
    async def doData(self,data):
        self.get_protocol().handleData(data)
    
    async def lowerClose(self):
        if self.finTimer:
            self.finTimer.cancel()
        if not self.loop.is_closed():
            self.lowerTransport().close()
        
    def _close(self):
        for el in self.sendStack:
            el[0].cancel()
        self.synTimer.cancel()
        if self.finTimer:
            self.finTimer.cancel()
        self.state = "CLOSED"
        if not self.loop.is_closed():
            time.sleep(1)
            asyncio.run_coroutine_threadsafe(self.lowerClose(), self.loop)
        
    @staticmethod
    def next_seq(packet):
        # really not right.
        if RippTransport._has_load(packet):
            return packet.SeqNo + len(packet.Data)
        elif 'SYN' in packet.Type or 'FIN' in packet.Type:
            return packet.SeqNo + 1
        else:
            return packet.SeqNo

    def handle(self, packet):
        c = packet.CRC
        packet.CRC = b''
        s = packet.__serialize__()
        m = hashlib.sha256()
        m.update(s)
        if m.digest() != c:
            return
        packet.CRC = c

        recvType = packet.Type
        if self._has_load(packet):
            if self.state == "ESTABLISHED" or self.state =="FIN-SENT":

                with self.prevAckCond and self.pktBufferCond:
                    if packet.SeqNo < self.prevAck:
                        return

                    for pkt in self.packetBuffer:
                        if packet.CRC == pkt.CRC:
                            return
                    
                    self.addToPacketBuffer(packet)
                    if self.timer._started:
                        self.timer.cancel();
                        self.timer = createRecvTimer(self)
                    self.timer.start()
        else:
#             with self.prevAckCond:
            if "SYN" in recvType:
                self.prevAck = max(self.next_seq(packet), self.prevAck)

                if self.state == "LISTEN":
                    self.state = "SYN-RECEIVED"
                    self._send_ack(Type="SYN")
                elif self.state == "SYN-SENT":
                    self.seq += 1
                    self.state = "ESTABLISHED"
                    self._send_ack()
                    self.get_protocol().RippEstablished()
                    self.synTimer.cancel()
#                     print(str(self._extra['peername'][1]) + ": " + "Got synack. Canceling syn timer")
            elif "FIN" in recvType:
#                     print("GOT FIN")
#                     print("state: " + self.state)
                if self.state == "ESTABLISHED":
                    self.send_finack()
                elif self.state == "FIN-SENT":
                    self.finTimer.cancel()
#                     print(str(self._extra['peername'][1]) + ": " + "Got Fin and Fin-sent, closing immediately")
                    self._close()
            elif "ACK" in recvType:
                if self.state == "SYN-RECEIVED":
                    self.state = "ESTABLISHED"
                    self.get_protocol().RippEstablished()
                    self.synTimer.cancel()
                elif self.state == "ESTABLISHED":
                    if packet.AckNo < self.seq:
                        with self.seqCond:
                            for [t,_,pos] in self.sendStack:
                                if pos <= packet.AckNo:
                                    t.cancel()
                    elif packet.AckNo == self.seq:
                        self.getMore();
                elif "FIN" in recvType and self.state == "FIN-SENT":
                    self.finTimer.cancel()
#                     print(str(self._extra['peername'][1]) + ": " + "Got Fin-ACK and Fin-sent, closing immediately")
                    self._close()
                                                     
            else:
                raise BadPacketError("Oh no!")
        
    #try to handle the rest of the stuff in the buffer when we haven't gotten a good packet for a little bit
    
    def tryBuffer(self):
        with self.pktBufferCond and self.prevAckCond:
            pkts = self.cleanBuffer();
            for pkt in pkts:
#                 self.get_protocol().handleData(pkt.Data)
                asyncio.run_coroutine_threadsafe(self.doData(pkt.Data), self.loop)
                self.prevAck = pkt.SeqNo
                self.pktsProcessed += 1
            self._send_ack()
            
    def cleanBuffer(self):
        self.packetBuffer[:] = [pkt for pkt in self.packetBuffer if (pkt.SeqNo > self.prevAck)]

        ret = []
        tmpAck = self.prevAck
        for pkt in self.packetBuffer:
            if len(pkt.Data) + tmpAck == pkt.SeqNo:
                tmpAck = pkt.SeqNo;
                ret.append(pkt)
        return ret
        
                
            
    def addToPacketBuffer(self, packet):
        if len(self.packetBuffer) == 0:
            self.packetBuffer.append(packet)
        else:
            self.packetBuffer.append(packet)
            self.packetBuffer.sort(key=lambda x: x.SeqNo, reverse=False)

    def addToSendStack(self,load):
        #send stack will look like (timer, count, payload position)
        with self.seqCond:
            self.seq+=len(load)
            self.sendStack.append([createSendTimer(self,load,len(self.sendStack)),0,self.seq])
            self.trySend(load,len(self.sendStack)-1)
    
    def trySend(self,load,idx):
        if self.loop.is_closed():
            return
        if self.state != "ESTABLISHED":
            return
        self._send_data(load=load,idx=idx,seq=self.sendStack[idx][2])
        self.sendStack[idx][1] += 1;
        
        ##WE DON'T HAVE RESET SO WE'RE JUST GONNA CLOSE THE CONNECTION SINCE IT FAILED TO SEND
        if self.sendStack[idx][1] == 30:
            self.get_protocol().close()
            return
        self.sendStack[idx][0].cancel()
        self.sendStack[idx][0]=createSendTimer(self,load,idx)
        self.sendStack[idx][0].start()
    
    def getMore(self):
        with self.sendStackCond:
            for el in self.sendStack:
                el[0].cancel()
            self.sendStack = []

            for i in range (0,16):
                if self.dataToSend:
                    self.addToSendStack(self.dataToSend.pop(0))
            
            
    
    #payload here is the SERIALIZED data from the higher layer.  We just need to write it.
    def write(self, payload):
        # Block
        while self.state != "ESTABLISHED":
            time.sleep(0.1)
        #Could also use some sort of timeout here   
        numPackets = math.ceil(len(payload) / 1500.00);
#         print(str(self._extra['peername'][1]) + ": " +"numPackets: ", numPackets)
        cnt = 0
        for i in range (1,numPackets+1):
            if i == numPackets:
#                 print(str(self._extra['peername'][1]) + ": " +"should be sending payload: ", payload[cnt:len(payload)])
                self.dataToSend.append(payload[cnt:len(payload)])
            else:
                self.dataToSend.append(payload[cnt:i*1500])
            cnt = i * 1500;
        if len(self.sendStack) == 0:
            self.getMore()
