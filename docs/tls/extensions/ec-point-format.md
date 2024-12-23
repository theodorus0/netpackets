[TLS Extensions](../extensions.md)
# Elliptic curve point format TLS extension
[RFC 8422 section 5.1.2](https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1.2)

| Format             | Value |
|--------------------|-------|
| Uncompressed       | 0     |
| (deprecated value) | 1     |
| (deprecated value) | 2     |

For backwards compatibility purposes, the point format list extension MAY
still be included and contain exactly one value: the uncompressed
point format (0).

RFC 4492 specified that if this extension is
missing, it means that only the uncompressed point format is
supported, so interoperability with implementations that support the
uncompressed format should work with or without the extension.

## How to use in netpackets

```python
class ECPointFormatList:
    type = 11
    length: int
    list_length: int
    formats: list[ECPointFormat]
```
where `list_length` is format list length in bytes