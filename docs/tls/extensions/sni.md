[TLS Extensions](../extensions.md)
# Server name indication TLS extension
[RFC 6066 section 3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3)

In order to provide any of the server names, clients MAY include an
extension of type "server_name" in the (extended) client hello.
The "extension_data" field of this extension SHALL contain:

| Field              | Size, bytes |
|--------------------|-------------|
| List size in bytes | 2           |
| Names list         | variable    |

The "Names list" MUST NOT contain more than one name of the same
name_type.

List elements have the following structure:

| Field       | Size, bytes |
|-------------|-------------|
| Name type   | 1           |
| Name length | 2           |
| Name        | variable    |

Where "name" field is just string containing target hostname.

"Name type" is a constant, only allowed value is Hostname (0).
Literal IPv4 and IPv6 addresses are not permitted in "HostName".

If an application negotiates a server name using an application
protocol and then upgrades to TLS, and if a server_name extension is
sent, then the extension SHOULD contain the same name that was
negotiated in the application protocol. If the server_name is
established in the TLS session handshake, the client SHOULD NOT
attempt to request a different server name at the application layer.

## How to use in netpackets

```python
class ServerNameIndication:
    type = 0
    length: int
    list_length: int
    names: list[ServerName]
```