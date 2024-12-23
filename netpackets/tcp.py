import socket
import struct
from collections.abc import Iterable
from enum import IntFlag
from typing import Optional

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
    __source_port: int
    __destination_port: int
    __sequence_number: int
    __acknowledgment_number: int
    __flags: list[TCPFlags]
    __window_size: int
    __urgent_pointer: int
    __options: bytes
    __data: bytes
    __source_ip: str
    __dest_ip: str
    __checksum: Optional[int]

    def __init__(self, *, src_port: int = 0, dest_port: int = 0,
                 seq: int = 0, ack: int = 0,
                 window_size: int = 0,
                 flags: Iterable[TCPFlags] = None,
                 data: bytes = b'',
                 options: bytes = b'',
                 urgent_pointer: int = 0,
                 source_ip: str = '0.0.0.0', dest_ip: str = '0.0.0.0'):
        self.source_port = src_port
        self.destination_port = dest_port
        self.sequence_number = seq
        self.acknowledgment_number = ack
        self.reserved = 0
        self.flags = flags if flags is not None else []
        self.window_size = window_size
        self.urgent_pointer = urgent_pointer
        self.options = options
        self.data = data
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.__checksum = None

    @property
    def data_offset(self):
        return (20 + len(self.options)) // 4

    @staticmethod
    def parse(data: bytes) -> 'TCPPacket':

        (source_port,
         destination_port,
         sequence_number,
         acknowledgment_number,
         header_len_and_flags,
         window_size,
         checksum,
         urgent_pointer) = struct.unpack('!HHII4H', data[:20])

        flags = parse_flags(header_len_and_flags & 0x1FF)
        header_length = (header_len_and_flags >> 12) & 0xF

        options_length = header_length * 4 - 20

        if options_length > 0:
            options = data[20: 20 + options_length]
        else:
            options = b""

        packet = TCPPacket(src_port=source_port,
                           dest_port=destination_port,
                           seq=sequence_number,
                           ack=acknowledgment_number,
                           window_size=window_size,
                           flags=flags,
                           options=options,
                           urgent_pointer=urgent_pointer,
                           data=data[header_length * 4:])
        packet.checksum = checksum
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

    def calculate_checksum(self):
        pseudo_header = struct.pack(
            '!4s4sxBH',
            socket.inet_aton(self.source_ip),
            socket.inet_aton(self.dest_ip),
            6,
            self.data_offset * 4 + len(self.data)
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

    @property
    def data(self):
        return self.__data

    @data.setter
    def data(self, data: bytes):
        self.__data = data
        self.__checksum = None
        self.__sublayer = None

    @property
    def source_port(self):
        return self.__source_port

    @source_port.setter
    def source_port(self, port: int):
        self.__source_port = port
        self.__checksum = None

    @property
    def destination_port(self):
        return self.__destination_port

    @destination_port.setter
    def destination_port(self, port: int):
        self.__destination_port = port
        self.__checksum = None

    @property
    def sequence_number(self):
        return self.__sequence_number

    @sequence_number.setter
    def sequence_number(self, seq: int):
        self.__sequence_number = seq
        self.__checksum = None

    @property
    def acknowledgment_number(self):
        return self.__acknowledgment_number

    @acknowledgment_number.setter
    def acknowledgment_number(self, ack: int):
        self.__acknowledgment_number = ack
        self.__checksum = None

    @property
    def flags(self):
        return self.__flags

    @flags.setter
    def flags(self, flags: list[TCPFlags]):
        self.__flags = flags
        self.__checksum = None

    @property
    def window_size(self):
        return self.__window_size

    @window_size.setter
    def window_size(self, window_size: int):
        self.__window_size = window_size
        self.__checksum = None

    @property
    def urgent_pointer(self):
        return self.__urgent_pointer

    @urgent_pointer.setter
    def urgent_pointer(self, urgent_pointer: int):
        self.__urgent_pointer = urgent_pointer
        self.__checksum = None

    @property
    def options(self):
        return self.__options

    @options.setter
    def options(self, options: bytes):
        self.__options = options
        self.__checksum = None

    @property
    def source_ip(self):
        return self.__source_ip

    @source_ip.setter
    def source_ip(self, source_ip: str):
        self.__source_ip = source_ip
        self.__checksum = None

    @property
    def dest_ip(self):
        return self.__dest_ip

    @dest_ip.setter
    def dest_ip(self, dest_ip: str):
        self.__dest_ip = dest_ip
        self.__checksum = None

    @property
    def checksum(self):
        if self.__checksum is None:
            print('before update: ', self.__checksum)
            self.__checksum = self.calculate_checksum()
            print('updating chksum: ', self.__checksum)
        else:
            print("basic", self.__checksum)
        return self.__checksum

    @checksum.setter
    def checksum(self, value: int):
        self.__checksum = value
