import socket
import struct

from netpackets import IPPacket, TCPPacket, TCPFlags


def test_build():
    source_ip = "1.1.1.1"
    destination_ip = "2.2.2.2"
    payload = b"Hello, World!"

    packet = IPPacket(source=source_ip, dest=destination_ip, payload=payload)
    built_packet = packet.build()

    # Unpack the built packet to verify its contents
    version_and_ihl, tos, total_length, identification, flags_and_fragment_offset, \
        ttl, protocol, header_checksum, source_ip_bytes, destination_ip_bytes = \
        struct.unpack_from('!BBHHHBBH4s4s', built_packet[:20])

    assert version_and_ihl >> 4 == 4  # IPv4
    assert tos == 0
    assert total_length == len(built_packet)
    assert identification == packet.identification
    assert flags_and_fragment_offset >> 13 == packet.flags
    assert ttl == 128
    assert protocol == 6  # TCP
    assert header_checksum == packet.header_checksum
    assert socket.inet_ntoa(source_ip_bytes) == source_ip
    assert socket.inet_ntoa(destination_ip_bytes) == destination_ip
    assert built_packet[20:] == payload


def test_ip_packet_with_tcp_payload():
    source_ip = "1.1.1.1"
    destination_ip = "2.2.2.2"
    tcp_payload = b"Hello, TCP!"

    tcp_packet = TCPPacket(
        src_port=12345,
        dest_port=80,
        seq=1000,
        ack=1000,
        window_size=1024,
        flags=[TCPFlags.SYN],
        data=tcp_payload
    )
    ip_packet = IPPacket(source=source_ip, dest=destination_ip, payload=(tcp_packet.build()))
    built_packet = ip_packet.build()

    version_and_ihl, tos, total_length, identification, flags_and_fragment_offset, \
        ttl, protocol, header_checksum, source_ip_bytes, destination_ip_bytes = \
        struct.unpack_from('!BBHHHBBH4s4s', built_packet[:20])

    assert version_and_ihl >> 4 == 4
    assert tos == 0
    assert total_length == len(built_packet)
    assert identification == ip_packet.identification
    assert flags_and_fragment_offset >> 13 == ip_packet.flags
    assert ttl == 128
    assert protocol == 6  # TCP
    assert header_checksum == ip_packet.header_checksum
    assert socket.inet_ntoa(source_ip_bytes) == source_ip
    assert socket.inet_ntoa(destination_ip_bytes) == destination_ip
    assert built_packet[20:] == tcp_packet.build()

    # Unpack the TCP packet from the IP packet payload to verify its contents
    unpacked_tcp_packet = TCPPacket.parse(built_packet[20:])
    assert unpacked_tcp_packet.source_port == tcp_packet.source_port
    assert unpacked_tcp_packet.destination_port == tcp_packet.destination_port
    assert unpacked_tcp_packet.sequence_number == tcp_packet.sequence_number
    assert unpacked_tcp_packet.acknowledgment_number == tcp_packet.acknowledgment_number
    assert unpacked_tcp_packet.window_size == tcp_packet.window_size
    assert unpacked_tcp_packet.flags == tcp_packet.flags
    assert unpacked_tcp_packet.options == b""
    assert unpacked_tcp_packet.data_offset == 5
    assert unpacked_tcp_packet.data == tcp_payload
