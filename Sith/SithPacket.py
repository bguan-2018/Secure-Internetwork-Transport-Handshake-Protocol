from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT8, UINT16, UINT32, STRING, BUFFER, LIST
from playground.network.packet.fieldtypes.attributes import Optional

class SithPacket(PacketType):

   DEFINITION_IDENTIFIER = "SITH.kandarp.packet"

   DEFINITION_VERSION = "1.0"

   FIELDS = [


     ("Type", STRING), # HELLO, FINISH, DATA, CLOSE

     ("Random", BUFFER({Optional: True})),

     ("PublicValue", BUFFER({Optional: True})),

     ("Certificate", LIST(BUFFER)({Optional: True})),

     ("Signature", BUFFER({Optional: True})),

     ("Ciphertext", BUFFER({Optional: True}))

   ]