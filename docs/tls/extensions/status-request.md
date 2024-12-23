[TLS Extensions](../extensions.md)
# Certificate status request TLS extension

[RFC 6066 section 8](https://www.rfc-editor.org/rfc/rfc6066.html#section-8)

In order to indicate their desire to receive certificate status
information, clients MAY include an extension of type
"status_request" in the (extended) client hello.

"extension_data" field of this extension has such structure:

| Field                | Size, bytes |
|----------------------|-------------|
| Status Type          | 1           |
| Responder IDs length | 2           |
| Responder IDs        | variable    |
| Extensions length    | 2           |
| Extensions           | variable    |

Status type is a constant, the only possible value at the moment is 1 (OCSP).

Both "ResponderID" and "Extensions" are [DER-encoded ASN.1 types](https://en.wikipedia.org/wiki/ASN.1#Example_encoded_in_DER) as
defined in [RFC2560]. "Extensions" is imported from [RFC5280].

A zero-length "request_extensions" value means that there are no
extensions (as opposed to a zero-length ASN.1 SEQUENCE, which is not
valid for the "Extensions" type).

## How to use in netpackets
```python
class StatusRequest:
    type = 5
    length: int
    certificate_status_type: CertificateStatusType
    
    responder_ids_length: int
    responder_ids: list = []
    
    request_extensions_length: int
    request_extensions: list = []
```