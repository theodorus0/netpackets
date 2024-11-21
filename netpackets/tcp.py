import socket
import struct
from collections.abc import Iterable
from enum import IntFlag

from netpackets.packet import Packet


class TCPFlags(IntFlag):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80
    NS = 0x100


def parse_flags(value: int) -> list[TCPFlags]:
    flags = []
    for flag in TCPFlags:
        if value & flag:
            flags.append(flag)
    return flags


class TCPPacket(Packet):
    def __init__(self, *, src_port: int = 0, dest_port: int = 0,
                 seq: int = 0, ack: int = 0,
                 window_size: int = 0,
                 flags: Iterable[TCPFlags] = None,
                 data: bytes = b'',
                 options: bytes = b'',
                 source_ip: str = '0.0.0.0', dest_ip: str = '0.0.0.0'):
        self.source_port = src_port
        self.destination_port = dest_port
        self.sequence_number = seq
        self.acknowledgment_number = ack
        self.reserved = 0
        self.flags = flags if flags is not None else []
        self.window_size = window_size
        self.urgent_pointer = 0
        self.options = options
        self.data = data
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.checksum = self.update_checksum()

    @property
    def data_offset(self):
        return (20 + len(self.options)) // 4

    @staticmethod
    def parse(data: bytes) -> 'TCPPacket':
        packet = TCPPacket()

        (packet.source_port,
         packet.destination_port,
         packet.sequence_number,
         packet.acknowledgment_number,
         header_len_and_flags,
         packet.window_size,
         packet.checksum,
         packet.urgent_pointer) = struct.unpack('!HHII4H', data[:20])

        header_length = (header_len_and_flags >> 12) & 0xF

        flags = header_len_and_flags & 0x1FF
        packet.flags = parse_flags(flags)

        options_length = header_length * 4 - 20

        if options_length > 0:
            packet.options = data[20: 20 + options_length]
        packet.data = data[header_length * 4:]

        return packet

    def build(self, use_checksum: bool = True) -> bytes:
        header_and_flags = (self.data_offset << 12) | (sum(self.flags))

        header = struct.pack(
            '!HHII4H',
            self.source_port,
            self.destination_port,
            self.sequence_number,
            self.acknowledgment_number,
            header_and_flags,
            self.window_size,
            self.checksum if use_checksum else 0,
            self.urgent_pointer)

        return header + self.options + self.data

    def update_checksum(self):
        pseudo_header = struct.pack(
            '!4s4sxBH',
            socket.inet_aton(self.source_ip),
            socket.inet_aton(self.dest_ip),
            6,
            self.data_offset*4 + len(self.data)
        )
        checksum_data = pseudo_header + self.build(False)

        if len(checksum_data) % 2 != 0:
            checksum_data += b'\x00'

        checksum = 0

        for word, in struct.iter_unpack('!H', checksum_data):
            checksum += word

        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)

        return (~checksum) & 0xFFFF
