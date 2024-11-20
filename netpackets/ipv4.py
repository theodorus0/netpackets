import random
import socket
import struct
from math import ceil
from typing import Optional

from netpackets import TCPPacket
from netpackets.packet import Packet


def bit_not(n):
    return (1 << n.bit_length()) - 1 - n


class IPPacket(Packet):
    version: int
    type_of_service: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    header_checksum: int
    source_ip: str
    destination_ip: str
    options: bytes
    data: bytes

    dont_fragment: bool
    more_fragments: bool

    @property
    def header_checksum(self):
        header = struct.pack('!BBHHHBBH',
                             (self.version << 4) + (self.header_length // 4),
                             self.type_of_service,
                             self.total_length,
                             self.identification,
                             (self.flags << 13) + self.fragment_offset,
                             self.ttl,
                             self.protocol,
                             0)
        chksum = 0
        for word, in struct.iter_unpack("H", header):
            chksum += word
        carry = chksum // 0x10000
        return bit_not(chksum % 0x10000 + carry)

    @property
    def flags(self):
        return (self.dont_fragment << 1) | self.more_fragments

    @property
    def header_length(self):
        actual_length = 20 + len(self.options)
        return ceil(actual_length / 4) * 4

    @property
    def total_length(self):
        return self.header_length + len(self.data)

    def __init__(self, *, source: str = "0.0.0.0", dest: str = "255.255.255.255", payload: bytes = b""):
        self.version = 4
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
        if self.protocol != 6:
            raise NotImplementedError(f"Can't decode IPPROTO: {self.protocol}")
        return TCPPacket.parse(self.data)
