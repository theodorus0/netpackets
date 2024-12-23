from netpackets.tls.extension import TLSExtension, ExtensionType, register_extension


@register_extension
class ExtendedMasterSectet(TLSExtension):
    type = ExtensionType.extended_master_secret
    length = 0

    def build_content(self) -> bytes:
        return b""

    @staticmethod
    def parse_content(raw: bytes):
        return ExtendedMasterSectet()
