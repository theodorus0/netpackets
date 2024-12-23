# Internet protocol version 4

| Field                         | Size     | Optimisation                          | Resets checksum |
|-------------------------------|----------|---------------------------------------|-----------------|
| Version                       | 4 bits   | Constant value                        |                 |
| Header size (in 32-bit words) | 4 bits   | Computed on every access              |                 |
| Type of service               | 8 bits   |                                       | +               |
| Total length                  | 2 bytes  | Computed on every access              |                 |
| Identifier                    | 2 byte   |                                       | +               |
| Flags                         | 3 bits   | Computed on every access              |                 |
| Fragment offset               | 13 bits  |                                       | +               |
| TTL                           | 1 byte   |                                       | +               |
| Protocol                      | 1 byte   |                                       | +               |
| Header checksum               | 2 bytes  | Computed only when checksum was reset |                 |
| Source address                | 4 bytes  |                                       | +               |
| Destination address           | 4 bytes  |                                       | +               |
| Options                       | variable |                                       | +               |
| Data                          | variable |                                       | Not header      |

**Keep in mind that IPPacket class provides header length in bytes, not in 32-bit blocks** 