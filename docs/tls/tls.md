# Transport Layer Security

TLS is a protocol used to exchange data securely using encryption.
TLS stream consists of 2 stages:
1. Handshake. Client and server choose encryption methods and other connection parameters.
2. Data transfer

Both these stages use their own packet format.
Also, there is a TLS Alert Protocol to indicate errors that happen during TLS exchange   

In summary, the standard defines several record types:
- [Handshake](handshake.md)
- Alert
- ChangeCipherSpec
- Application protocol

## Idea of TLS protocol
Main idea is that there is no single "TLS packet" that has flags or fields.
TLS is a _standard_ that defines several protocols, such as **TLS Handshake protocol** and **ChangeCipherSpec protocol**.

Each of these protocols define a record packet that carries one or multiple messages.
Each message represents information transferred between two sides.

For example, in Handshake protocol client sends a ClientHello message. 
