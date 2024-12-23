import struct

from netpackets.tls.extension import TLSExtension, ExtensionType, register_extension
from netpackets.tls.record import TLSVersion


@register_extension
class SupportedVersions(TLSExtension):
    type = ExtensionType.supported_versions
    versions: list[TLSVersion]

    def __init__(self, versions: list[TLSVersion]):
        self.versions = versions

    @property
    def list_length(self):
        return len(self.versions) * 2

    @property
    def length(self):
        return self.list_length + 1

    def build_content(self) -> bytes:
        result = struct.pack("!B", self.list_length)
        for ver in self.versions:
            result += struct.pack("!H", ver)
        return result

    @staticmethod
    def parse_content(raw: bytes):
        length, = struct.unpack_from("!B", raw)
        versions = []
        for ver, in struct.iter_unpack("!H", raw[1:1 + length]):
            versions.append(TLSVersion(ver))
        return SupportedVersions(versions)
