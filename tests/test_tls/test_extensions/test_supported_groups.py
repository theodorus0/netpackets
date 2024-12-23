import pytest

from netpackets.tls.extensions.supported_groups import SupportedGroups, EncryptionGroup


@pytest.mark.parametrize(("hex_data", "groups"),
                         [
                             ("0006001d00170018",
                              [EncryptionGroup.x25519, EncryptionGroup.secp256r1, EncryptionGroup.secp384r1])
                         ])
def test_parse(hex_data, groups):
    sg = SupportedGroups.parse_content(bytes.fromhex(hex_data))
    assert sg.groups == groups
    assert sg.length == 8


@pytest.mark.parametrize(("hex_data", "groups"),
                         [
                             ("0006001d00170018",
                              [EncryptionGroup.x25519, EncryptionGroup.secp256r1, EncryptionGroup.secp384r1])
                         ])
def test_build_content(hex_data, groups):
    sg = SupportedGroups(groups)
    assert sg.build_content().hex() == hex_data


@pytest.mark.parametrize(("hex_data", "groups"),
                         [
                             ("000a00080006001d00170018",
                              [EncryptionGroup.x25519, EncryptionGroup.secp256r1, EncryptionGroup.secp384r1])
                         ])
def test_build(hex_data, groups):
    sg = SupportedGroups(groups)
    assert sg.build().hex() == hex_data
