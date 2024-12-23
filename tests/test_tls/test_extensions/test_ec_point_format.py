import pytest

from netpackets.tls.extensions.ec_point_format import ECPointFormatList, ECPointFormat


@pytest.mark.parametrize(("hex_data", "formats"),
                         [
                             ("0100",
                              [ECPointFormat.Uncompressed])
                         ])
def test_parse(hex_data, formats):
    ecpf = ECPointFormatList.parse_content(bytes.fromhex(hex_data))
    assert ecpf.formats == formats
    assert ecpf.length == 2


@pytest.mark.parametrize(("hex_data", "formats"),
                         [
                             ("0100",
                              [ECPointFormat.Uncompressed])
                         ])
def test_build_content(hex_data, formats):
    ecpf = ECPointFormatList(formats)
    assert ecpf.build_content().hex() == hex_data


@pytest.mark.parametrize(("hex_data", "formats"),
                         [
                             ("000b00020100",
                              [ECPointFormat.Uncompressed])
                         ])
def test_build(hex_data, formats):
    ecpf = ECPointFormatList(formats)
    assert ecpf.build().hex() == hex_data
