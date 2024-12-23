import pytest

from netpackets.tls.extensions import ALPN


@pytest.mark.parametrize(("hex_data", "protocols"),
                         [
                             ("000908687474702f312e31",
                              ["http/1.1"])
                         ])
def test_parse(hex_data, protocols):
    alpn = ALPN.parse_content(bytes.fromhex(hex_data))
    assert alpn.protocols == protocols
    assert alpn.length == 11


@pytest.mark.parametrize(("hex_data", "protocols"),
                         [
                             ("000908687474702f312e31",
                              ["http/1.1"])
                         ])
def test_build_content(hex_data, protocols):
    alpn = ALPN(protocols)
    assert alpn.build_content().hex() == hex_data


@pytest.mark.parametrize(("hex_data", "protocols"),
                         [
                             ("0010000b000908687474702f312e31",
                              ["http/1.1"])
                         ])
def test_build(hex_data, protocols):
    alpn = ALPN(protocols)
    assert alpn.build().hex() == hex_data
