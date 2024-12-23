import pytest

from netpackets.tls.extensions.server_name import ServerNameIndication, ServerName


@pytest.mark.parametrize(("hex_data", "names"),
                         [
                             ("000d00000a676f6f676c652e636f6d", [('google.com', 0)])
                         ], ids=["google.com"])
def test_parse(hex_data, names):
    sni = ServerNameIndication.parse_content(bytes.fromhex(hex_data))
    for actual, should in zip(sni.names, names):
        assert actual.server_name == should[0]
        assert actual.name_type == should[1]

    assert sni.length == 15


@pytest.mark.parametrize(("hex_data", "names"),
                         [
                             ("000d00000a676f6f676c652e636f6d", [('google.com', 0)])
                         ], ids=["google.com"])
def test_build_content(hex_data, names):
    sni = ServerNameIndication([ServerName(*name) for name in names])
    assert sni.build_content().hex() == hex_data


@pytest.mark.parametrize(("hex_data", "names"),
                         [
                             ("0000000f000d00000a676f6f676c652e636f6d", [('google.com', 0)])
                         ], ids=["google.com"])
def test_build(hex_data, names):
    sni = ServerNameIndication([ServerName(*name) for name in names])
    assert sni.build().hex() == hex_data
