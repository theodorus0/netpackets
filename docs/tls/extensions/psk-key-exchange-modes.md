[TLS Extensions](../extensions.md)

# PSK key exchange modes TLS extension

[RFC 8446 section 4.2.9](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.9)

| Field       | Size, bytes |
|-------------|-------------|
| List length | 1           |
| List        | variable    |

List contains one-byte elements:

| PskKeyExchangeMode | Value |
|--------------------|-------|
| PSK-only           | 0     |
| PSK with (EC)DHE   | 1     |

## How to use in netpackets

```python
class PSKKeyExchangeModes:
    type = 45
    length: int
    modes: list[PSKExchangeMode]
```