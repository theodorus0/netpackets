import pytest

from netpackets.tls.extensions.status_request import StatusRequest, CertificateStatusType


@pytest.mark.parametrize(("hex_data", "fields"),
                         [
                             ("0100000000", (CertificateStatusType.OSCP, [], []))
                         ])
def test_parse(hex_data, fields):
    sr = StatusRequest.parse_content(bytes.fromhex(hex_data))
    assert sr.certificate_status_type == fields[0]
    assert sr.responder_ids == fields[1]
    assert sr.request_extensions == fields[2]
    assert sr.length == 5


@pytest.mark.parametrize(("hex_data", "fields"),
                         [
                             ("0100000000", (CertificateStatusType.OSCP, [], []))
                         ])
def test_build_content(hex_data, fields):
    sr = StatusRequest(fields[0])
    assert sr.build_content().hex() == hex_data

@pytest.mark.parametrize(("hex_data", "fields"),
                         [
                             ("000500050100000000", (CertificateStatusType.OSCP, [], []))
                         ])
def test_parse(hex_data, fields):
    sr = StatusRequest(fields[0])
    assert sr.build().hex() == hex_data

