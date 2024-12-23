import pytest

from netpackets.tls.extensions import KeyShareClientHello
from netpackets.tls.extensions.supported_groups import EncryptionGroup


@pytest.mark.parametrize(("hex_data", "keys"),
                         [
                             ("0024001d00203757892ae5611cf157fe22f91b20af5ff36f0392209d3add64c8b4f6fdebc029",
                              {EncryptionGroup.x25519: bytes.fromhex(
                                  '3757892ae5611cf157fe22f91b20af5ff36f0392209d3add64c8b4f6fdebc029')})
                         ])
def test_parse(hex_data, keys):
    ks = KeyShareClientHello.parse_content(bytes.fromhex(hex_data))
    assert ks.keys == keys
    assert ks.length == 38


@pytest.mark.parametrize(("hex_data", "keys"),
                         [
                             ("0024001d00203757892ae5611cf157fe22f91b20af5ff36f0392209d3add64c8b4f6fdebc029",
                              {EncryptionGroup.x25519: bytes.fromhex(
                                  '3757892ae5611cf157fe22f91b20af5ff36f0392209d3add64c8b4f6fdebc029')})
                         ])
def test_build_content(hex_data, keys):
    ks = KeyShareClientHello(keys)
    assert ks.build_content().hex() == hex_data


@pytest.mark.parametrize(("hex_data", "keys"),
                         [
                             ("003300260024001d00203757892ae5611cf157fe22f91b20af5ff36f0392209d3add64c8b4f6fdebc029",
                              {EncryptionGroup.x25519: bytes.fromhex(
                                  '3757892ae5611cf157fe22f91b20af5ff36f0392209d3add64c8b4f6fdebc029')})
                         ])
def test_build(hex_data, keys):
    ks = KeyShareClientHello(keys)
    assert ks.build().hex() == hex_data
