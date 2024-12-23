import pytest

from netpackets.tls.client_hello import ClientHello, TLSCipherSuite, TLSCompressionMethod
from netpackets.tls.extensions import ServerName, StatusRequest, SupportedVersions, SignatureAlgorithms, SessionTicket, \
    SupportedGroups, ECPointFormatList, ALPN, KeyShareClientHello, PostHandshakeAuth, ExtendedMasterSectet, \
    RenegotiationInfo, PSKKeyExchangeModes
from netpackets.tls.extensions.ec_point_format import ECPointFormat
from netpackets.tls.extensions.psk_key_exchange_modes import PSKExchangeMode
from netpackets.tls.extensions.server_name import ServerNameIndication
from netpackets.tls.extensions.signature_algorithms import SignHashAlgo
from netpackets.tls.extensions.status_request import CertificateStatusType
from netpackets.tls.extensions.supported_groups import EncryptionGroup
from netpackets.tls.record import TLSVersion

e = [
    ServerNameIndication([ServerName("google.com")]),
    StatusRequest(CertificateStatusType.OSCP),
    SupportedVersions([TLSVersion.TLS13, TLSVersion.TLS12, TLSVersion.TLS11, TLSVersion.TLS10]),
    SignatureAlgorithms([
        SignHashAlgo.rsa_pss_rsae_sha256,
        SignHashAlgo.rsa_pss_rsae_sha384,
        SignHashAlgo.rsa_pss_rsae_sha512,
        SignHashAlgo.rsa_pkcs1_sha256,
        SignHashAlgo.rsa_pkcs1_sha384,
        SignHashAlgo.rsa_pkcs1_sha1,
        SignHashAlgo.ecdsa_secp256r1_sha256,
        SignHashAlgo.ecdsa_secp384r1_sha384,
        SignHashAlgo.ecdsa_sha1,
        SignHashAlgo.SHA1_DSA,
        SignHashAlgo.rsa_pkcs1_sha512,
        SignHashAlgo.ecdsa_secp521r1_sha512,

    ]
    ),
    SessionTicket(),
    SupportedGroups([EncryptionGroup.x25519, EncryptionGroup.secp256r1, EncryptionGroup.secp384r1]),
    ECPointFormatList([ECPointFormat.Uncompressed]),
    ALPN(["http/1.1"]),
    KeyShareClientHello(
        {EncryptionGroup.x25519: bytes.fromhex("3757892ae5611cf157fe22f91b20af5ff36f0392209d3add64c8b4f6fdebc029")}),
    PostHandshakeAuth(),
    ExtendedMasterSectet(),
    RenegotiationInfo(),
    PSKKeyExchangeModes([PSKExchangeMode.psk_dhe])
]


@pytest.mark.parametrize("hex_data", [
    "03031c689fd72ea8e7f5282b4aa97b0dae2f1d55f8d81ec1e37950168aaeaa9ed0c0208527ca3b6f1e4aa5f75555b7226b79a01ad5e159aa08662caf5c3cc71e8c1ffd002813021301c02cc02bc030c02fc024c023c028c027c00ac009c014c013009d009c003d003c0035002f010000a90000000f000d00000a676f6f676c652e636f6d000500050100000000002b0009080304030303020301000d001a001808040805080604010501020104030503020302020601060300230000000a00080006001d00170018000b000201000010000b000908687474702f312e31003300260024001d00203757892ae5611cf157fe22f91b20af5ff36f0392209d3add64c8b4f6fdebc0290031000000170000ff01000100002d00020101"
], ids=["google.com"])
def test_parse(hex_data: str):
    ch = ClientHello.parse_handshake_message(bytes.fromhex(hex_data))

    random = bytes.fromhex("1c689fd72ea8e7f5282b4aa97b0dae2f1d55f8d81ec1e37950168aaeaa9ed0c0")
    session_id = bytes.fromhex("8527ca3b6f1e4aa5f75555b7226b79a01ad5e159aa08662caf5c3cc71e8c1ffd")
    t = ClientHello(TLSVersion.TLS13,
                    random,
                    session_id,
                    [
                        TLSCipherSuite.TLS_AES_256_GCM_SHA384,
                        TLSCipherSuite.TLS_AES_128_GCM_SHA256,
                        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                        TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                        TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
                        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                        TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                        TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                        TLSCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                        TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                        TLSCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                        TLSCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                        TLSCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                        TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                        TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                        TLSCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                        TLSCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    ],
                    [TLSCompressionMethod.Null],
                    e)
    assert ch.build_handshake_message().hex() == t.build_handshake_message().hex()
