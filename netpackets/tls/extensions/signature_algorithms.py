import struct
from enum import IntEnum

from netpackets.tls.extension import TLSExtension, register_extension, ExtensionType


class SignHashAlgo(IntEnum):
    rsa_pkcs1_sha256 = 0x0401
    rsa_pkcs1_sha384 = 0x0501
    rsa_pkcs1_sha512 = 0x0601
    ecdsa_secp256r1_sha256 = 0x0403
    ecdsa_secp384r1_sha384 = 0x0503
    ecdsa_secp521r1_sha512 = 0x0603

    rsa_pss_rsae_sha256 = 0x0804
    rsa_pss_rsae_sha384 = 0x0805
    rsa_pss_rsae_sha512 = 0x0806
    ed25519 = 0x0807
    ed448 = 0x0808
    rsa_pss_pss_sha256 = 0x0809
    rsa_pss_pss_sha384 = 0x080a
    rsa_pss_pss_sha512 = 0x080b
    rsa_pkcs1_sha1 = 0x0201
    SHA1_DSA = 0x0202
    ecdsa_sha1 = 0x0203


@register_extension
class SignatureAlgorithms(TLSExtension):
    type = ExtensionType.signature_algorithms
    alorithms: list[SignHashAlgo]

    @property
    def length(self):
        return len(self.alorithms) * 2 + 2

    def __init__(self, algos: list[SignHashAlgo]):
        self.alorithms = algos

    def build_content(self) -> bytes:
        result = struct.pack("!H", len(self.alorithms) * 2)
        for algo in self.alorithms:
            result += struct.pack("!H", algo)
        return result

    @staticmethod
    def parse_content(raw: bytes):
        length, = struct.unpack_from("!H", raw)
        alorithms = []
        for hash_sign, in struct.iter_unpack("!H", raw[2:2 + length]):
            alorithms.append(SignHashAlgo(hash_sign))
        return SignatureAlgorithms(alorithms)
