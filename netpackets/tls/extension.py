import struct
from abc import abstractmethod
from enum import IntEnum


class ExtensionType(IntEnum):
    server_name = 0
    max_fragment_length = 1
    status_request = 5
    supported_groups = 10
    ec_point_formats = 11
    signature_algorithms = 13
    use_srtp = 14
    heartbeat = 15
    application_layer_protocol_negotiation = 16
    signed_certificate_timestamp = 18
    client_certificate_type = 19
    server_certificate_type = 20
    padding = 21
    extended_master_secret = 23
    session_ticket = 35
    pre_shared_key = 41
    early_data = 42
    supported_versions = 43
    cookie = 44
    psk_key_exchange_modes = 45
    certificate_authorities = 47
    oid_filters = 48
    post_handshake_auth = 49
    signature_algorithms_cert = 50
    key_share = 51
    renegotiation_info = 0xff01


class TLSExtension:
    type: ExtensionType
    length: int

    def build(self) -> bytes:
        content = self.build_content()
        return struct.pack("!HH", self.type, self.length) + content

    @abstractmethod
    def build_content(self) -> bytes:
        raise NotImplemented

    @staticmethod
    @abstractmethod
    def parse_content(raw: bytes):
        raise NotImplemented


__mapping: dict[int, type[TLSExtension]] = {}


def register_extension(cls: type[TLSExtension]):
    """Decorator to map extension type to extension class"""
    __mapping[cls.type] = cls
    return cls


def parse_extension_by_type(extension_type: ExtensionType, data: bytes) -> TLSExtension:
    return __mapping[extension_type.value].parse_content(data)
