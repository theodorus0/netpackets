[TLS Extensions](../extensions.md)
# Supported versions TLS extension

[RFC 8446 section 4.2.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.1)

Used:
- by the client to indicate which versions of TLS it supports 
- by the server to indicate which version it is using

| Field              | Size, bytes |
|--------------------|-------------|
| List size in bytes | 1           |
| Versions           | variable    |
Each element of the list is 2-byte TLS version value

## Client's implementation

Implementations of this specification MUST send this extension in the
ClientHello containing all versions of TLS which they are prepared to
negotiate (for this specification, that means minimally 0x0304, but
if previous versions of TLS are allowed to be negotiated, they MUST
be present as well).

If this extension is not present, servers which are compliant with
this specification and which also support TLS 1.2 MUST negotiate
TLS 1.2 or prior as specified in [RFC5246], even if
ClientHello.legacy_version is 0x0304 or later.  Servers MAY abort the
handshake upon receiving a ClientHello with legacy_version 0x0304 or
later.

## Server's implementation
A server which negotiates a version of TLS prior to TLS 1.3 MUST set
ServerHello.version and MUST NOT send the "supported_versions"
extension.  A server which negotiates TLS 1.3 MUST respond by sending
a "supported_versions" extension containing the selected version
value (0x0304).  It MUST set the ServerHello.legacy_version field to
0x0303 (TLS 1.2).  Clients MUST check for this extension prior to
processing the rest of the ServerHello (although they will have to
parse the ServerHello in order to read the extension).  If this
extension is present, clients MUST ignore the
ServerHello.legacy_version value and MUST use only the
"supported_versions" extension to determine the selected version.  If
the "supported_versions" extension in the ServerHello contains a
version not offered by the client or contains a version prior to
TLS 1.3, the client MUST abort the handshake with an
"illegal_parameter" alert.

## How to use in netpackets

```python
class SupportedVersions:
    type = 43
    length: int
    list_length: int
    versions: list[TLSVersion]
```