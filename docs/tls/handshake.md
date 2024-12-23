# TLS Handshake protocol

## TLS 1.3 Handshake process
Main phases are:
1. Client sends [ClientHello](client-hello.md)
2. Server responses with ServerHello
3. Server sends ChangeCipherSpec to switch into encrypted mode
4. Client sends ChangeCipherSpec to switch into encrypted mode

## Handshake protocol
Handshake protocol allows to exchange data during TLS handshake,
so client and server can choose encryption methods, protocols and so on.

TLS Handshake protocol defines the following structure:

| Field              | Size, bytes | Comment                                      |
|--------------------|-------------|----------------------------------------------|
| Content type       | 1           | Value is set to 0x16                         |
| Major version      | 1           | until v1.3 used to identify protocol version |
| Minor version      | 1           | until v1.3 used to identify protocol version |
| Length             | 2           | Length of "Handshake messages"               |
| Handshake messages | variable    |                                              |

Handshake packet can contain several handshake messages, each
of them is defined the following way:

| Field                         | Size, bytes | Comment                               |
|-------------------------------|-------------|---------------------------------------|
| Message type                  | 1           | A constant, values are provided below |
| Handshake message data length | 3           |                                       |
| Handshake message data        | variable    |                                       |

Depending on handshake phase, different message types might be used:

| Message type	 | Description                         |
|---------------|-------------------------------------|
| 0             | 	HelloRequest                       |
| 1             | 	[ClientHello](client-hello.md)     |
| 2             | 	ServerHello                        |
| 4             | 	NewSessionTicket                   |
| 8             | 	EncryptedExtensions (TLS 1.3 only) |
| 11            | 	Certificate                        |
| 12            | 	ServerKeyExchange                  |
| 13            | 	CertificateRequest                 |
| 14            | 	ServerHelloDone                    |
| 15            | 	CertificateVerify                  |
| 16            | 	ClientKeyExchange                  |
| 20            | 	Finished                           |
