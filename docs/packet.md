# Packet

Base class for all packets
It provides basic interface to manipulate packets:

## build()
Build binary data from `Packet` object
```python
build(self) -> bytes
```
Each class overrides this method

## parse()
Static method to parse packet from binary data.
```python
parse(raw: bytes) -> Packet
```
You should parse data only if you are sure what are you doing.
In case data is not a correct packet of given type, you should consider behaviour undefined (it might return invalid packet or raise an error as well)

## sublayer property
Returns payload `Packet`.
```python
sublayer -> Packet | None
```

This property is cached. At the first time when `sublayer` is called it computes the value.
Subsequent calls will use cached value of this property until packet's `data` field is changed
