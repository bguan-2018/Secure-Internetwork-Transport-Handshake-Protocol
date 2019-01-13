#!/usr/bin/env python3

import playground.network.common as common
from .SithTransport import SithTransport
from .SithPacket import SithPacket
from playground.network.packet import PacketType


class SithClientProtocol(common.StackingProtocol):

    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(self.peername))
        print("Sith Protocol Initiated")
        self.transport = transport
        self._deserializer = SithPacket.Deserializer()
        self.thisTransport = SithTransport(self.transport, self)
        self.dataBuffer = b''
        self.thisTransport.connect()

    def data_received(self, data):
        # Deserialize data then pass it to the transport to handle it
        print(str(self.peername[1]) + ' Received Data')
        #         print(str(self.peername[1]) + ' data:  ' + str(data))
        self._deserializer.update(data)
# 
        for packet in self._deserializer.nextPackets():
            self.thisTransport.handle(packet)

    def close(self):
        print(str(self.peername[1]) + ' Sith protocol closed method called')
        self.thisTransport.close()

    def handleData(self, data):
#         self.dataBuffer += data;
        #         print("protocol handling data")
        self.higherProtocol().data_received(data)

    def connection_lost(self, exc):
        print(str(self.peername[1]) + " sith connection lost")
        self.higherProtocol().connection_lost(self)
        self.thisTransport = None

    def SithEstablished(self):
        print(str(self.peername[1]) + " sith established")
        self.higherProtocol().connection_made(self.thisTransport)

