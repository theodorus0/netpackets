from netpackets.tls.client_hello import ClientHello
from netpackets.tls.handshake import TLSHandshakeRecord
from netpackets.tls.record import TLSVersion
from tests.test_tls.test_client_hello import e
raw = bytes.fromhex(
    "160301011e0100011a03031c689fd72ea8e7f5282b4aa97b0dae2f1d55f8d81ec1e37950168aaeaa9ed0c0208527ca3b6f1e4aa5f75555b7226b79a01ad5e159aa08662caf5c3cc71e8c1ffd002813021301c02cc02bc030c02fc024c023c028c027c00ac009c014c013009d009c003d003c0035002f010000a90000000f000d00000a676f6f676c652e636f6d000500050100000000002b0009080304030303020301000d001a001808040805080604010501020104030503020302020601060300230000000a00080006001d00170018000b000201000010000b000908687474702f312e31003300260024001d00203757892ae5611cf157fe22f91b20af5ff36f0392209d3add64c8b4f6fdebc0290031000000170000ff01000100002d00020101")


def test_parse():
    h = TLSHandshakeRecord.parse(raw)
    assert h.content_type == 22
    assert h.legacy_version == TLSVersion.TLS10
    assert len(h.handshake_messages) == 1
    client_hello: ClientHello = h.handshake_messages[0]
    assert client_hello.message_type == 1
    assert client_hello.legacy_session_id_length == 32
    assert client_hello.cipher_suites_length == 40
    assert client_hello.extensions_length == 169
    assert client_hello.length == 282

