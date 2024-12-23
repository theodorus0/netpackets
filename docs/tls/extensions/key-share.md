[TLS Extensions](../extensions.md)

# Key share TLS extension

[RFC 8466 section 4.2.8](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8)

The "key_share" extension contains the endpoint's cryptographic
parameters.

## ClientHello message

| Extension data field | Size, bytes |
|----------------------|-------------|
| List length          | 2           |
| List                 | variable    |

| Key share field     | Size, bytes |
|---------------------|-------------|
| Group               | 2           |
| Key exchange length | 2           |
| Key exchange        | variable    |

Each group is the group from [Supported Groups](supported-groups.md) extension

## HelloRetryRequest message

In case of retry-request it contains just group ID:

| Extension data field | Size, bytes |
|----------------------|-------------|
| Group                | 2           |

## ServerHello message

Server, in its turn, replies with single KeyShare entry:

| Extension data field | Size, bytes |
|----------------------|-------------|
| Group                | 2           |
| Key exchange length  | 2           |
| Key exchange         | variable    |

## How to use in netpackets

```python

class KeyShareClientHello:
    type = 51
    length: int
    list_length: int
    keys: dict[EncryptionGroup, bytes]
```