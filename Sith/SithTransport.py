from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, \
    X25519PublicKey
from cryptography.hazmat.backends import default_backend
from .SithPacket import SithPacket
import secrets, hashlib, time
import playground.network.common as common

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .SithCertificate import load_certicate_chain, verify_certificate_chain


# THE TRANSPORT IS THE SAME LAYER AS THE PROTOCOL
class SithTransport(common.StackingTransport):
    def __init__(self, lowerTransport, protocol):
        super().__init__(lowerTransport)
        self.protocol = protocol
        self.state = "LISTENING"
        self.otherRandom = None
        self.myRandom = None
        self.otherPublic = None
        self.myPublic = None
        self.myPrivate = None
        self.backend = default_backend()
        self.myCert = None;
        self.dataBuffer = b'';
        self.sharedSecret = None;
        self.handshakeHash = None;
        self.myIV = None
        self.otherIV = None
        self.myWriteKey = None
        self.myReadKey = None
        self.amClient = 1

        self.initKeysAndRandomAndCert()

    def initKeysAndRandomAndCert(self):
        # INITIALIZE CERTIFICATE HERE
        self.myCert = load_certicate_chain()
        # initialize rest of private/public keys and random
        self.myPrivate = X25519PrivateKey.generate()
        self.myPublic = self.myPrivate.public_key()
        self.myRandom = secrets.token_bytes(32)

    def initIVs(self):
        h = hashlib.sha256()
        h.update(self.sharedSecret + self.handshakeHash)
        s = h.digest()
        if self.amClient:
            # 96 bits
            self.myIV = s[:12]
            # 96 - 192 bits
            self.otherIV = s[12:24]
        else:
            self.otherIV = s[:12]
            self.myIV = s[12:24]
        print("Iv's initiated with length: " + str(len(s)))

    def initAesKeys(self):
        h = hashlib.sha256()
        h.update(self.sharedSecret + self.handshakeHash)
        hd = h.digest()
        print("my h: " + str(hd))
        z = hashlib.sha256()
        z.update(hd)
        s = z.digest()
        print("my zd: " + str(s))

        # 128 bits
        if self.amClient:
            self.myWriteKey = s[16:]
            self.myReadKey = s[:16]
        else:
            self.myWriteKey = s[:16]
            self.myReadKey = s[16:]
        print("AES keys established")

    def get_protocol(self):
        return self.protocol

    def send_hello(self):
        packet = SithPacket()
        packet.Type = "HELLO"
        packet.PublicValue = self.myPublic.public_bytes()
        packet.Random = self.myRandom
        packet.Certificate = self.myCert

        ser = packet.__serialize__()
        self.dataBuffer += ser

        print(str(self._extra['peername'][1]) + ": " + " writing sith hello")

        self._lowerTransport.write(ser)
        self.state = "HELLO-SENT"

    def send_finish(self):
        # should be sending a signature of the handshake hash, needs to be updated
        packet = SithPacket()
        packet.Type = "FINISH"
        packet.Signature = self.handshakeHash;

        ser = packet.__serialize__()
        self.dataBuffer += ser

        print(str(self._extra['peername'][1]) + ": " + " writing sith finish")
        print(str(self._extra['peername'][1]) + ": " + " writing sith signature " + str(packet.Signature))

        self._lowerTransport.write(ser)
        self.state = "FINISH-SENT"

    def send_close(self):
        packet = SithPacket()
        packet.Type = "CLOSE"
        ser = packet.__serialize__()
        self._lowerTransport.write(ser)

    def decryptData(self, ciphertext):
#         print("decrypting data")
#         print(len(ciphertext))
#         ctext = ciphertext[:-16]
#         tag = ciphertext[-16:]
#         print(str(ctext))
#         print("tag: " + str(tag))
#         print("my readkey: " + str(self.myReadKey))
#         print("other iv: " + str(self.otherIV))
#         decryptor = Cipher(
#             algorithms.AES(self.myReadKey),
#             modes.GCM(self.otherIV, tag),
#             backend=default_backend()
#         ).decryptor()
#         print("done decrypting")
#         try:
        aesgcm = AESGCM(self.myReadKey)
#         r = decryptor.update(ctext) + decryptor.finalize()
#         except BaseException as e:
#             print("error decrypting")
#             print(e)
#         print("data decrypted to: " + str(r))
#         print("tryna decrypt")
#         try:
        r = aesgcm.decrypt(self.otherIV, ciphertext, None)
#         except BaseException as e:
#             print("error decrypting")
#             print(e)
#         print("decrypted data: " + r)
        self.get_protocol().handleData(r)

    def encryptDataAndSend(self, payload):
#         print("encrypting data")
#         print(payload)
#         print("my writekey: " + str(self.myWriteKey))
#         print("my iv: " + str(self.myIV))
        packet = SithPacket()
        packet.Type = "DATA"
        
#         encryptor = Cipher(
#             algorithms.AES(self.myWriteKey),
#             modes.GCM(self.myIV),
#             backend=default_backend()
#         ).encryptor()
        aesgcm = AESGCM(self.myWriteKey)
#         ciphertext = encryptor.update(payload) + encryptor.finalize()
        
        packet.Ciphertext = aesgcm.encrypt(self.myIV, payload, None)
#         packet.Ciphertext = ciphertext + encryptor.tag
#         print(encryptor.tag)
        ser = packet.__serialize__()
        self._lowerTransport.write(ser)

    def connect(self):
        #         print(str(self._extra['peername'][1]) + ": " + " sending sith hello!")
        self.send_hello()

    def close(self):
        self.state = "CLOSED"
        self.send_close()
        self.lowerTransport().close()

    def handle(self, packet):
        print(str(self._extra['peername'][1]) + ": " + " received sith data")
        print(str(self._extra['peername'][1]) + ": " + "  sith data type: " + packet.Type)
        print(str(self._extra['peername'][1]) + ": " + " sith state - " + self.state)
        if packet.Type == "CLOSE":
            self.state = "CLOSING"
            self.close()
        if self.state == "LISTENING":
            if packet.Type != "HELLO":
                self.close()
                return False
            # Validate certificate here:
            if not verify_certificate_chain(packet.Certificate):
                self.close();
                return False
            self.amClient = 0
            self.otherRandom = packet.Random
            self.otherPublic = X25519PublicKey.from_public_bytes(packet.PublicValue)

            self.sharedSecret = self.myPrivate.exchange(self.otherPublic)

            self.dataBuffer += packet.__serialize__();

            self.send_hello()

            h = hashlib.sha256()
            h.update(self.dataBuffer)
            self.handshakeHash = h.digest()
            self.initIVs()
            self.initAesKeys()

        elif self.state == "HELLO-SENT":

            if packet.Type == "HELLO":
                # Validate certificate here:
                if not verify_certificate_chain(packet.Certificate):
                    self.close();
                    return False
                self.otherRandom = packet.Random
                self.otherPublic = X25519PublicKey.from_public_bytes(packet.PublicValue)

                self.sharedSecret = self.myPrivate.exchange(self.otherPublic)

                self.dataBuffer += packet.__serialize__()

                h = hashlib.sha256()
                h.update(self.dataBuffer)
                self.handshakeHash = h.digest()
                #                 print("my hello handshake hash: " + str(self.handshakeHash))
                self.initIVs()
                self.initAesKeys()

                self.send_finish()

                z = hashlib.sha256()
                z.update(self.dataBuffer)
                self.handshakeHash = z.digest()

            elif packet.Type == "FINISH":
                print(str(self._extra['peername'][1]) + ": " + " sith first finish type " + packet.Type)

                # validate signature here:
                if packet.Signature != self.handshakeHash:
                    self.close();
                    return False

                self.dataBuffer += packet.__serialize__();
                h = hashlib.sha256()
                h.update(self.dataBuffer)
                self.handshakeHash = h.digest()

                self.send_finish()
                self.state = "ESTABLISHED"
                self.get_protocol().SithEstablished()

            else:
                self.close()
                return False

        elif self.state == "FINISH-SENT":
            print(str(self._extra['peername'][1]) + ": " + " sith packet type " + packet.Type)

            if packet.Type == "FINISH":

                # validate signature here:
                if packet.Signature != self.handshakeHash:
                    self.close();
                    return False

                self.dataBuffer += packet.__serialize__();
                h = hashlib.sha256()
                h.update(self.dataBuffer)
                self.handshakeHash = h.digest()

                self.state = "ESTABLISHED"
                self.get_protocol().SithEstablished()

            elif packet.Type == "DATA":
                self.decryptData(packet.Ciphertext)
            else:
                self.close();
                return False
        elif self.state == "ESTABLISHED":
            if packet.Type == "DATA":
                self.decryptData(packet.Ciphertext)
        print(self.state)

    def write(self, payload):
        # could potentially switch this to wait until write key is available
        print(str(self._extra['peername'][1]) + ": " + " sith write called")
        while self.state != "ESTABLISHED":
            time.sleep(0.1)
        print(str(self._extra['peername'][1]) + ": " + " writing sith payload")
        self.encryptDataAndSend(payload)


