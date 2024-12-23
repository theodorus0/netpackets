from netpackets.tls.extension import TLSExtension, ExtensionType, register_extension


@register_extension
class SessionTicket(TLSExtension):
    type = ExtensionType.session_ticket

    @property
    def length(self):
        return 0

    def build_content(self) -> bytes:
        return b""

    @staticmethod
    def parse_content(raw: bytes):
        return SessionTicket()
