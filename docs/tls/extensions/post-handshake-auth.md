[TLS Extensions](../extensions.md)
# Post-handshake client authentication TLS extension
[RFC 8466 section 4.2.6](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.6)

The "post_handshake_auth" extension is used to indicate that a client
is willing to perform post-handshake authentication (Section 4.6.2).

Servers MUST NOT send a post-handshake CertificateRequest to clients
which do not offer this extension. Servers MUST NOT send this
extension.

Extension data is empty.