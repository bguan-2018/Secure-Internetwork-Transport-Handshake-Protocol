#!/usr/bin/env python3

import playground.network.common as common
from .RippTransport import RippTransport
from .RippPacket import RippPacket
from playground.network.packet import PacketType


class RippProtocol(common.StackingProtocol):
    def __init__(self):
        self.transport = None
        super().__init__()

    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(self.peername))
        print('"HIIIIII BEEEENNNNNN"')
        self.transport = transport
        self.thisTransport = RippTransport(self.transport, self)
        self.dataBuffer = b''
        self.thisTransport.connect()

    def data_received(self, data):
        # Deserialize data then pass it to the transport to handle it
        print(str(self.peername[1]) + ' Received Data')
        #         print(str(self.peername[1]) + ' data:  ' + str(data))
        deserializer = RippPacket.Deserializer()
        deserializer.update(data)

        for packet in deserializer.nextPackets():
            self.thisTransport.handle(packet)

    def send_data(self, data):
        self.transport.write(data)

    def open(self):
        self.transport.bind()

    def close(self):
        print(str(self.peername[1]) + ' protocol closed method called')
        self.thisTransport.close()

    def handleData(self, data):
        self.dataBuffer += data;
        #         print("protocol handling data")
        self.higherProtocol().data_received(data)

    def connection_lost(self, exc):
        print(str(self.peername[1]) + " connection lost")
        self.higherProtocol().connection_lost(self)
        self.thisTransport = None

    def RippEstablished(self):
        self.higherProtocol().connection_made(self.thisTransport)
