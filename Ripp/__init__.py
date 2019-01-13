from playground.network.common import Protocol as p
from .RippProtocol import RippProtocol
import playground

prot = p.StackingProtocolFactory(lambda: RippProtocol())
ptConnector = playground.Connector(protocolStack=(prot))
playground.setConnector("Ripp", ptConnector)
