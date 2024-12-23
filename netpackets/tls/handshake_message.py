import struct
from abc import abstractmethod
from enum import IntEnum


class HandshakeMessageType(IntEnum):
    HelloRequest = 0
    ClientHello = 1
    ServerHello = 2
    NewSessionTicket = 4
    EncryptedExtensions = 8
    Certificate = 11
    ServerKeyExchange = 12
    CertificateRequest = 13
    ServerHelloDone = 14
    CertificateVerify = 15
    ClientKeyExchange = 16
    Finished = 20


class TLSHandshakeMessage:
    message_type: HandshakeMessageType
    message_data: bytes

    @property
    @abstractmethod
    def length(self):
        pass

    @property
    def message_length(self):
        return 4 + self.length

    @staticmethod
    @abstractmethod
    def parse_handshake_message(raw: bytes) -> "TLSHandshakeMessage":
        pass

    @abstractmethod
    def build_handshake_message(self) -> bytes:
        pass

    def build(self):
        msg = self.build_handshake_message()
        result = struct.pack("!B3s", self.message_type, bytes.fromhex(f"{len(msg):0>6x}"))
        return result + msg
