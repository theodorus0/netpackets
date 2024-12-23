from netpackets.tls.extension import TLSExtension, ExtensionType, register_extension


@register_extension
class PostHandshakeAuth(TLSExtension):
    type = ExtensionType.post_handshake_auth
    length = 0

    def build_content(self) -> bytes:
        return b""

    @staticmethod
    def parse_content(raw: bytes):
        return PostHandshakeAuth()
