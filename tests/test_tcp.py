from netpackets import TCPPacket, TCPFlags

packet_bytes_as_string = "ff41005021f6a88f000000008002faf05c950000020405b40103030801010402"
packet_no_chksum_bytes_as_string = "ff41005021f6a88f000000008002faf000000000020405b40103030801010402"
options_bytes_as_string = "020405b40103030801010402"
correct_packet = TCPPacket(
    src_port=65345,
    dest_port=80,
    seq=569813135,
    window_size=64240,
    flags=[TCPFlags.SYN],
    options=bytes.fromhex(options_bytes_as_string),
    source_ip='192.168.1.162',
    dest_ip='173.194.221.101',
)
correct_packet.checksum = 0x5c95


def __generate_packet():
    return TCPPacket(
        src_port=correct_packet.source_port,
        dest_port=correct_packet.destination_port,
        seq=correct_packet.sequence_number,
        ack=correct_packet.acknowledgment_number,
        window_size=correct_packet.window_size,
        flags=correct_packet.flags,
        source_ip='192.168.1.162',
        dest_ip='173.194.221.101',
        options=correct_packet.options
    )


def test_data_offset():
    assert correct_packet.data_offset == 8


def test_parse():
    raw = bytes.fromhex(packet_bytes_as_string)
    packet = TCPPacket.parse(raw)

    assert packet.source_port == correct_packet.source_port
    assert packet.destination_port == correct_packet.destination_port
    assert packet.sequence_number == correct_packet.sequence_number
    assert packet.acknowledgment_number == correct_packet.acknowledgment_number
    assert packet.window_size == correct_packet.window_size
    assert packet.checksum == correct_packet.checksum
    assert packet.urgent_pointer == correct_packet.urgent_pointer
    assert packet.flags == correct_packet.flags
    assert packet.options == correct_packet.options
    assert packet.data_offset == correct_packet.data_offset


def test_build_no_checksum():
    packet = __generate_packet()
    raw = bytes.fromhex(packet_no_chksum_bytes_as_string)
    assert packet.build(False).hex() == raw.hex()


def test_checksum():
    packet = __generate_packet()
    assert packet.checksum == correct_packet.checksum, 'wrong checksum'


def test_build():
    packet = __generate_packet()
    raw = bytes.fromhex(packet_bytes_as_string)
    assert packet.build().hex() == raw.hex()
