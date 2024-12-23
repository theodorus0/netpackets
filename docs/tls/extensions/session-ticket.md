[TLS Extensions](../extensions.md)
# Session ticket TLS extension
[RFC 5077 section 3.2](https://www.rfc-editor.org/rfc/rfc5077.html#section-3.2)
## Client side
If the client possesses a ticket that it wants to use to resume a
session, then it includes the ticket in the SessionTicket extension
in the ClientHello.

If the client does not have a ticket and is
prepared to receive one in the NewSessionTicket handshake message,
then it MUST include a zero-length ticket in the SessionTicket
extension.  If the client is not prepared to receive a ticket in the
NewSessionTicket handshake message, then it MUST NOT include a
SessionTicket extension unless it is sending a non-empty ticket it
received through some other means from the server.

## Server side
The server uses a zero-length SessionTicket extension to indicate to
the client that it will send a new session ticket using the
NewSessionTicket handshake message described in Section 3.3.

The server MUST send this extension in the ServerHello if it wishes to
issue a new ticket to the client using the NewSessionTicket handshake
message.  The server MUST NOT send this extension if it does not
receive one in the ClientHello.


## How to use in netpackets

```python
class SessionTicket:
    type = 35
    length = 0
```