[TLS Extensions](../extensions.md)
# Signature algorithms TLS extension
[RFC 8446 section 4.2.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3)

TLS 1.3 provides two extensions for indicating which signature
algorithms may be used in digital signatures.  The
"signature_algorithms_cert" extension applies to signatures in 
certificates, and the "signature_algorithms" extension, which
originally appeared in TLS 1.2, applies to signatures in
CertificateVerify messages.

| Field              | Size, bytes |
|--------------------|-------------|
| List size in bytes | 2           |
| Algorithms         | variable    |

Each algorithm described with 2 bytes:
- Hash algorithm byte
- Signature algorithm byte

Known alogithms are:

| Algorithm                                                 | Value  |            
|-----------------------------------------------------------|--------|
| RSASSA-PKCS1-v1_5 algorithms                              |        |
| rsa_pkcs1_sha256                                          | 0x0401 |
| rsa_pkcs1_sha384                                          | 0x0501 |
| rsa_pkcs1_sha512                                          | 0x0601 |
| ECDSA algorithms                                          |        | 
| ecdsa_secp256r1_sha256                                    | 0x0403 |
| ecdsa_secp384r1_sha384                                    | 0x0503 |
| ecdsa_secp521r1_sha512                                    | 0x0603 |
| RSASSA-PSS algorithms with public key OID rsaEncryption   |        | 
| rsa_pss_rsae_sha256                                       | 0x0804 |
| rsa_pss_rsae_sha384                                       | 0x0805 |
| rsa_pss_rsae_sha512                                       | 0x0806 |
| EdDSA algorithms                                          |        | 
| ed25519                                                   | 0x0807 |
| ed448                                                     | 0x0808 |
| RSASSA-PSS algorithms with public key OID RSASSA-PSS      | 
| rsa_pss_pss_sha256                                        | 0x0809 |
| rsa_pss_pss_sha384                                        | 0x080a |
| rsa_pss_pss_sha512                                        | 0x080b |
| Legacy algorithms                                         |        | 
| rsa_pkcs1_sha1                                            | 0x0201 |
| ecdsa_sha1                                                | 0x0203 |
          