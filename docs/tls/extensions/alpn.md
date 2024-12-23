[TLS Extensions](../extensions.md)
# Application-layer protocol negotiation TLS extension
[RFC 7301](https://www.rfc-editor.org/rfc/rfc7301.html)

When multiple application protocols are supported on a
single server-side port number, such as port 443, the client and the server need to
negotiate an application protocol for use with each connection.

It is desirable to accomplish this negotiation without adding network
round-trips between the client and the server, as each round-trip
will degrade an end-user's experience.
Further, it would be advantageous to allow certificate selection based on the negotiated
application protocol.

| Field                 | Size, bytes |
|-----------------------|-------------|
| ALPN extension length | 2           |
| ALPN protocols        | variable    |

Protocol list items are just strings with size:

| List item field    | Size, bytes |
|--------------------|-------------|
| String length      | 1           |
| ALPN protocol name | variable    |

## How to use in netpackets
Extension class is defined like this: 
```python
class ALPN:
    type = 16
    length: int
    list_length: int
    protocols: list[str]
```

where `list_lendth` is "ALPN extension length" from RFC,
basically it is the byte length of list