[TLS Extensions](../extensions.md)

# Renegotiation info TLS extension

[RFC 5746](https://www.rfc-editor.org/rfc/rfc5746.html#section-3.2)

Used to prevent renegotiation attack.

## Initial Client Hello and Server Hello

Extension data is empty

## Subsequent Client Hello

| Field              | Size, bytes       |
|--------------------|-------------------|
| Client verify data | 12 (36 for SSLv3) |

## Subsequent Server Hello

| Field              | Size, bytes       |
|--------------------|-------------------|
| Client verify data | 12 (36 for SSLv3) |
| Server verify data | 12 (36 for SSLv3) |

## How to use in netpackets

```python
class RenegotiationInfo:
    type = 0xff01
    length: int
    client_verify_data: bytes | None
    server_verify_data: bytes | None
```