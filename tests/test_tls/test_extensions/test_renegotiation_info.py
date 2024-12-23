import pytest

from netpackets.tls.extensions import RenegotiationInfo


@pytest.mark.parametrize(("hex_data", "client", "server"),
                         [
                             ("00", b"", b"")
                         ])
def test_parse(hex_data, client, server):
    rni = RenegotiationInfo.parse_content(bytes.fromhex(hex_data))
    assert rni.client_verify_data == client
    assert rni.server_verify_data == server
    assert rni.length == 1


@pytest.mark.parametrize(("hex_data", "client", "server"),
                         [
                            ("00", b"", b"")
                         ])
def test_build_content(hex_data, client, server):
    rni = RenegotiationInfo(client, server)
    assert rni.build_content().hex() == hex_data


@pytest.mark.parametrize(("hex_data", "client", "server"),
                         [
                             ("ff01000100", b"", b"")
                         ])
def test_build(hex_data, client, server):
    rni = RenegotiationInfo(client, server)
    assert rni.build().hex() == hex_data
