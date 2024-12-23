import pytest

from netpackets.tls.extensions import SupportedVersions
from netpackets.tls.record import TLSVersion


@pytest.mark.parametrize(("hex_data", "versions"),
                         [
                             ("080304030303020301",
                              ([TLSVersion.TLS13, TLSVersion.TLS12, TLSVersion.TLS11, TLSVersion.TLS10]))
                         ])
def test_parse(hex_data, versions):
    sv = SupportedVersions.parse_content(bytes.fromhex(hex_data))
    assert sv.versions == versions
    assert sv.length == 9


@pytest.mark.parametrize(("hex_data", "versions"),
                         [
                             ("080304030303020301",
                              ([TLSVersion.TLS13, TLSVersion.TLS12, TLSVersion.TLS11, TLSVersion.TLS10]))
                         ])
def test_build_content(hex_data, versions):
    sv = SupportedVersions(versions)
    assert sv.build_content().hex() == hex_data


@pytest.mark.parametrize(("hex_data", "versions"),
                         [
                             ("002b0009080304030303020301",
                              ([TLSVersion.TLS13, TLSVersion.TLS12, TLSVersion.TLS11, TLSVersion.TLS10]))
                         ])
def test_build(hex_data, versions):
    sv = SupportedVersions(versions)
    assert sv.build().hex() == hex_data
