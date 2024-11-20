from netpackets import TCPPacket, TCPFlags


def test_parse():
    raw = bytes.fromhex("833b01bbe3694ab8000000008002ffff677f0000020405b40103030801010402")
    packet = TCPPacket.parse(raw)

    assert packet.source_port == 33595
    assert packet.destination_port == 443
    assert packet.sequence_number == 3815328440
    assert packet.acknowledgment_number == 0
    assert packet.window_size == 65535
    assert packet.checksum == 0x677f
    assert packet.urgent_pointer == 0
    assert packet.flags == [TCPFlags.SYN]
    assert packet.options == bytes.fromhex("020405b40103030801010402")


def test_build():
    packet = TCPPacket(
        src_port=33595,
        dest_port=443,
        seq=3815328440,
        ack=0,
        window_size=65535,
        flags=[TCPFlags.SYN]
    )
    packet.options = bytes.fromhex("020405b40103030801010402")
    packet.checksum = 0x677f
    raw = bytes.fromhex("833b01bbe3694ab8000000008002ffff677f0000020405b40103030801010402")
    assert packet.build().hex() == raw.hex()
