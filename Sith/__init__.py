from playground.network.common import Protocol as p
from .SithServerProtocol import SithServerProtocol
from .SithClientProtocol import SithClientProtocol
from ..Ripp  import RippProtocol
import playground

sprot = p.StackingProtocolFactory(lambda: RippProtocol(), lambda: SithServerProtocol())
cprot = p.StackingProtocolFactory(lambda: RippProtocol(), lambda: SithClientProtocol())
ptConnector = playground.Connector(protocolStack=(cprot,sprot))
playground.setConnector("Sith", ptConnector)
