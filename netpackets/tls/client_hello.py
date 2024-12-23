import struct
from enum import IntEnum

from netpackets.tls.extensions import TLSExtension, parse_extension_by_type, ExtensionType
from netpackets.tls.handshake_message import TLSHandshakeMessage, HandshakeMessageType
from netpackets.tls.record import TLSVersion


class TLSCipherSuite(IntEnum):
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xc024
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xc023
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xc028
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xc027
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003d
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003c
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f


class TLSCompressionMethod(IntEnum):
    Null = 0
    Deflate = 1
    LZS = 64


def parse_extensions(offset: int, raw: bytes):
    ext_len, = struct.unpack_from("!H", raw, offset)
    offset += 2
    extensions = []
    ext_off = offset
    while ext_off < offset + ext_len:
        ext_type, extension_length = struct.unpack_from("!HH", raw, ext_off)
        extensions.append(parse_extension_by_type(ExtensionType(ext_type), raw[ext_off + 4:]))
        ext_off += 4 + extension_length
    return extensions


def parse_compression_methods(offset: int, raw: bytes):
    cm_len, = struct.unpack_from("!B", raw, offset)
    methods = []
    offset += 1
    for i in range(cm_len):
        cm, = struct.unpack_from("!B", raw, offset)
        methods.append(TLSCompressionMethod(cm))
        offset += 1
    return methods, offset


def parse_cipher_suites(offset: int, raw: bytes, sid_len: int):
    suites = []
    cs_len, = struct.unpack_from(f"!H", raw, offset)
    offset += 2
    while offset < 35 + sid_len + 2 + cs_len:
        cs, = struct.unpack_from("!H", raw, offset)
        suites.append(TLSCipherSuite(cs))
        offset += 2
    return suites, offset


class ClientHello(TLSHandshakeMessage):
    message_type = HandshakeMessageType.ClientHello
    legacy_version: TLSVersion
    random: bytes
    legacy_session_id: bytes
    cipher_suites: list[TLSCipherSuite]
    compression_methods: list[TLSCompressionMethod]
    extensions: list[TLSExtension]

    def __init__(self, ver: TLSVersion,
                 random: bytes,
                 session_id: bytes,
                 cipher_suites: list[TLSCipherSuite],
                 compression_methods: list[TLSCompressionMethod],
                 extensions: list[TLSExtension] = None):
        if extensions is None:
            extensions = []

        if ver > TLSVersion.TLS12:
            self.legacy_version = TLSVersion.TLS12
        else:
            self.legacy_version = ver
        self.random = random
        self.legacy_session_id = session_id
        self.cipher_suites = cipher_suites
        self.compression_methods = compression_methods
        self.extensions = extensions

    @property
    def legacy_session_id_length(self):
        return len(self.legacy_session_id)

    @property
    def cipher_suites_length(self):
        return 2 * len(self.cipher_suites)

    @property
    def compression_methods_length(self):
        return len(self.compression_methods)

    @property
    def extensions_length(self):
        return sum(4 + extension.length for extension in self.extensions)

    @property
    def length(self):
        return 2 + 32 \
            + 1 + self.legacy_session_id_length \
            + 2 + self.cipher_suites_length \
            + 1 + self.compression_methods_length \
            + 2 + self.extensions_length

    @staticmethod
    def parse_handshake_message(raw: bytes) -> "ClientHello":
        version_, random, sid_len, = struct.unpack_from("!H32sB", raw)

        offset = 35
        sid, = struct.unpack_from(f"!{sid_len}s", raw, offset)
        offset += sid_len

        suites, offset = parse_cipher_suites(offset, raw, sid_len)
        methods, offset = parse_compression_methods(offset, raw)
        extensions = parse_extensions(offset, raw)

        return ClientHello(TLSVersion(version_), random, sid, suites, methods, extensions)

    def build_handshake_message(self):
        result = struct.pack("!H32sB", self.legacy_version, self.random, self.legacy_session_id_length)
        result += self.legacy_session_id
        result += struct.pack("!H", self.cipher_suites_length)
        for cs in self.cipher_suites:
            result += struct.pack("!H", cs)
        result += struct.pack("!B", self.compression_methods_length)
        for cm in self.compression_methods:
            result += struct.pack("!B", cm)
        result += struct.pack("!H", self.extensions_length)
        for ext in self.extensions:
            result += ext.build()
        return result
