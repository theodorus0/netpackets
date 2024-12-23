# Transport control protocol

| Field                  | Size     | Resets checksum |
|------------------------|----------|-----------------|
| Source port            | 2 bytes  | +               |
| Destination port       | 2 bytes  | +               |
| Sequence number        | 4 bytes  | +               |
| Acknowledgement number | 4 bytes  | +               |
| Data offset            | 4 bits   |                 |
| Reserved (should be 0) | 3 bits   |                 |
| Flags                  | 9 bits   | +               |
| Window size            | 2 bytes  | +               |
| Checksum               | 2 bytes  | +               |
| Checksum               | 2 bytes  |                 |
| Urgent pointer         | 2 bytes  | +               |
| Options                | variable | +               |
| Data                   | variable | +               |