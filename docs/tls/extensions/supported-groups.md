[TLS Extensions](../extensions.md)

# Supported groups TLS extension

[RFC 8422 section 5.1.1](https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.1)

When sent by the client, the "supported_groups" extension indicates
the named groups which the client supports for key exchange, ordered
from most preferred to least preferred.

| Field       | Size, bytes |
|-------------|-------------|
| List length | 2           |
| Groups      | variable    |

| Group     | Value |
|-----------|-------|
| secp256r1 | 0x17  |
| secp384r1 | 0x18  |
| secp521r1 | 0x19  |
| x25519    | 0x1d  |
| x448      | 0x1e  |
| ffdhe2048 | 0x100 |
| ffdhe3072 | 0x101 |
| ffdhe4096 | 0x102 |
| ffdhe6144 | 0x103 |
| ffdhe8192 | 0x104 |

## How to use in netpackets

```python
class SupportedGroups:
    type = 10
    length: int
    list_length: int
    groups: list[EncryptionGroup]
```