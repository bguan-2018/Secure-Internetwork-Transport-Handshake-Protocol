from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT16, UINT32, STRING, BUFFER, LIST
from playground.network.packet.fieldtypes.attributes import Optional

class RippPacket(PacketType):
	
	DEFINITION_IDENTIFIER = "RIPP.kandarp.packet"
	DEFINITION_VERSION = "1.0"
	FIELDS = [
		("Type", STRING), #Should probably be String
		("SeqNo", UINT32),
		("AckNo", UINT32),
		("CRC", BUFFER),
		("Data", BUFFER)
	]