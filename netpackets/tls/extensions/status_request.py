import struct
from enum import IntEnum

from netpackets.tls.extension import TLSExtension, ExtensionType, register_extension


class CertificateStatusType(IntEnum):
    OSCP = 1


@register_extension
class StatusRequest(TLSExtension):
    type = ExtensionType.status_request

    certificate_status_type: CertificateStatusType

    responder_ids: list = []
    request_extensions: list = []

    def __init__(self, certificate_status_type: CertificateStatusType):
        self.certificate_status_type = certificate_status_type

    @property
    def length(self):
        return 5 + self.responder_ids_length + self.request_extensions_length

    @property
    def responder_ids_length(self):
        return len(self.responder_ids)

    @property
    def request_extensions_length(self):
        return len(self.request_extensions)

    def build_content(self) -> bytes:
        if self.responder_ids or self.request_extensions:
            raise NotImplemented("Non-empty 'responder_ids' and 'request_extensions' are not supported yet")
        return struct.pack("!BHH",
                           self.certificate_status_type,
                           self.responder_ids_length,
                           self.request_extensions_length)

    @staticmethod
    def parse_content(raw: bytes) -> "StatusRequest":
        # TODO: process responder IDs and request extensions

        (certificate_status_type,
         responder_ids_length,
         request_extensions_length) = struct.unpack_from("!BHH", raw)
        if responder_ids_length or request_extensions_length:
            raise NotImplemented("Non-empty 'responder_ids' and 'request_extensions' are not supported yet")
        sr = StatusRequest(certificate_status_type)
        return sr
