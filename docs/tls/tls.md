# Transport Layer Security

TLS is a protocol used to exchange data securely using encryption.
TLS stream consists of 2 stages:
1. Handshake. Client and server choose encryption methods and other connection parameters.
2. Data transfer

Both these stages use their own packet format.
Also, there is a TLS Alert Protocol to indicate errors that happen during TLS exchange   

## TLS record
A generic TLS record has following structure:

| Field                             | Size, bytes | Comment                                                     |
|-----------------------------------|-------------|-------------------------------------------------------------|
| Content type                      | 1           |                                                             |
| Major version                     | 1           | until v1.3 used to identify protocol version                |
| Minor version                     | 1           | until v1.3 used to identify protocol version                |
| Length                            | 2           | Length of "Data", "MAC" and "Padding" combined              |
| Data                              | variable    | Packet's payload, actual format is defined by content type  |
| Message authentication code (MAC) | variable    |                                                             |
| Padding                           | variable    |                                                             |


The standard defines several record types:
- [Handshake](handshake.md)
- Alert
- Application protocol