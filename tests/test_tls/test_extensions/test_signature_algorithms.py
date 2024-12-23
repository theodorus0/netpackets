import pytest

from netpackets.tls.extensions.signature_algorithms import SignatureAlgorithms, SignHashAlgo


@pytest.mark.parametrize(("hex_data", "alorithms"),
                         [
                             ("0018080408050806040105010201040305030203020206010603",
                              [
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
                              )
                         ])
def test_parse(hex_data, alorithms):
    sa = SignatureAlgorithms.parse_content(bytes.fromhex(hex_data))
    assert sa.alorithms == alorithms
    assert sa.length == 26
