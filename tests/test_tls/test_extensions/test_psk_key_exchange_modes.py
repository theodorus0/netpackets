import pytest

from netpackets.tls.extensions import PSKKeyExchangeModes


@pytest.mark.parametrize(("hex_data", "modes"),
                         [
                             ["0101", [1]]
                         ])
def test_parse(hex_data, modes):
    pskem = PSKKeyExchangeModes.parse_content(bytes.fromhex(hex_data))
    assert pskem.modes == modes
    assert pskem.length == 2


@pytest.mark.parametrize(("hex_data", "modes"),
                         [
                            ["0101", [1]]
                         ])
def test_build_content(hex_data, modes):
    pskem = PSKKeyExchangeModes(modes)
    assert pskem.build_content().hex() == hex_data


@pytest.mark.parametrize(("hex_data", "modes"),
                         [
                             ["002d00020101", [1]]
                         ])
def test_build(hex_data, modes):
    pskem = PSKKeyExchangeModes(modes)
    assert pskem.build().hex() == hex_data
