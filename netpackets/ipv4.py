import random
import socket
import struct

from typing import Optional

from netpackets import TCPPacket
from netpackets.packet import Packet


def bit_not(n):
    return (1 << n.bit_length()) - 1 - n


class IPPacket(Packet):
    version: int = 4
    __type_of_service: int
    __identification: int
    __fragment_offset: int
    __ttl: int
    __protocol: int
    __header_checksum: Optional[int]
    __source_ip: str
    __destination_ip: str
    __options: bytes
    __data: bytes

    __dont_fragment: bool
    __more_fragments: bool

    __sublayer: Optional[TCPPacket]

    @property
    def header_checksum(self):
        if self.__header_checksum is not None:
            return self.__header_checksum
        header = struct.pack('!BBHHHBBH4s4s',
                             (self.version << 4) + (self.header_length // 4),
                             self.type_of_service,
                             self.total_length,
                             self.identification,
                             (self.flags << 13) + self.fragment_offset,
                             self.ttl,
                             self.protocol,
                             0,
                             socket.inet_aton(self.source_ip),
                             socket.inet_aton(self.destination_ip))
        chksum = 0
        for word, in struct.iter_unpack("!H", header):
            chksum += word
        while chksum >> 16:
            chksum = (chksum & 0xFFFF) + (chksum >> 16)
        self.__header_checksum = (~chksum) & 0xFFFF
        return self.__header_checksum

    @header_checksum.setter
    def header_checksum(self, checksum: int):
        self.__header_checksum = checksum

    @property
    def flags(self):
        return (self.dont_fragment << 1) | self.more_fragments

    @property
    def header_length(self):
        return 20 + len(self.options)

    @property
    def total_length(self):
        return self.header_length + len(self.data)

    def __init__(self, *, source: str = "0.0.0.0", dest: str = "255.255.255.255", payload: bytes = b""):
        self.ttl = 128
        self.options = b''
        self.dont_fragment = True
        self.more_fragments = False
        self.fragment_offset = 0
        self.type_of_service = 0
        self.identification = random.randint(0, 65535)
        self.protocol = 6  # TCP
        self.source_ip = source
        self.destination_ip = dest
        self.data = payload
        self.__sublayer = None

    @staticmethod
    def parse(header_bytes: bytes) -> 'IPPacket':
        fields = struct.unpack_from('!BBHHHBBH', header_bytes[:20])
        version_and_ihl, tos, total_length, identification, flags_and_fragment_offset, \
            ttl, protocol, header_checksum = fields

        version = version_and_ihl >> 4
        header_length = (version_and_ihl & 0xF) * 4

        flags = flags_and_fragment_offset >> 13
        fragment_offset = flags_and_fragment_offset & 0x1FFF

        source_ip = socket.inet_ntoa(header_bytes[12:16])
        destination_ip = socket.inet_ntoa(header_bytes[16:20])

        options = header_bytes[20:header_length] if header_length > 20 else b''

        packet = IPPacket()
        packet.version = version
        packet.type_of_service = tos
        packet.identification = identification
        packet.dont_fragment = bool(flags & 0x2)
        packet.more_fragments = bool(flags & 0x1)
        packet.fragment_offset = fragment_offset
        packet.ttl = ttl
        packet.protocol = protocol
        packet.source_ip = source_ip
        packet.destination_ip = destination_ip
        packet.options = options
        packet.data = header_bytes[header_length:]

        return packet

    def build(self) -> bytes:
        source_ip_bytes = socket.inet_aton(self.source_ip)
        destination_ip_bytes = socket.inet_aton(self.destination_ip)

        header = struct.pack('!BBHHHBBH4s4s',
                             (self.version << 4) + (self.header_length // 4),
                             self.type_of_service,
                             self.total_length,
                             self.identification,
                             (self.flags << 13) + self.fragment_offset,
                             self.ttl,
                             self.protocol,
                             self.header_checksum,
                             source_ip_bytes,
                             destination_ip_bytes)
        if self.options:
            header += self.options

        packet_bytes = header + self.data
        return packet_bytes

    @property
    def sublayer(self) -> TCPPacket:
        if self.__sublayer is None:
            self.__sublayer = TCPPacket.parse(self.data)
        return self.__sublayer

    @property
    def data(self):
        return self.__data

    @data.setter
    def data(self, data: bytes):
        self.__data = data
        self.__sublayer = None

    @property
    def ttl(self):
        return self.__ttl

    @ttl.setter
    def ttl(self, ttl: int):
        self.__ttl = ttl
        self.__header_checksum = None

    @property
    def protocol(self):
        return self.__protocol

    @protocol.setter
    def protocol(self, protocol: int):
        if protocol != 6:
            raise NotImplementedError(f"Can't decode IPPROTO: {protocol}")
        self.__protocol = protocol
        self.__header_checksum = None

    @property
    def source_ip(self):
        return self.__source_ip

    @source_ip.setter
    def source_ip(self, source_ip: str):
        self.__source_ip = source_ip
        self.__header_checksum = None

    @property
    def destination_ip(self):
        return self.__destination_ip

    @destination_ip.setter
    def destination_ip(self, destination_ip: str):
        self.__destination_ip = destination_ip
        self.__header_checksum = None

    @property
    def options(self):
        return self.__options

    @options.setter
    def options(self, options: bytes):
        self.__options = options
        self.__header_checksum = None

    @property
    def dont_fragment(self):
        return self.__dont_fragment

    @dont_fragment.setter
    def dont_fragment(self, dont_fragment: bool):
        self.__dont_fragment = dont_fragment
        self.__header_checksum = None

    @property
    def more_fragments(self):
        return self.__more_fragments

    @more_fragments.setter
    def more_fragments(self, more_fragments: bool):
        self.__more_fragments = more_fragments
        self.__header_checksum = None

    @property
    def fragment_offset(self):
        return self.__fragment_offset

    @fragment_offset.setter
    def fragment_offset(self, fragment_offset: int):
        self.__fragment_offset = fragment_offset
        self.__header_checksum = None

    @property
    def type_of_service(self):
        return self.__type_of_service

    @type_of_service.setter
    def type_of_service(self, type_of_service: int):
        self.__type_of_service = type_of_service
        self.__header_checksum = None

    @property
    def identification(self):
        return self.__identification

    @identification.setter
    def identification(self, identification: int):
        self.__identification = identification
        self.__header_checksum = None
