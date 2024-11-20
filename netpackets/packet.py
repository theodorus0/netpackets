from abc import abstractmethod


class Packet:
    @abstractmethod
    def build(self) -> bytes:
        pass

    @staticmethod
    @abstractmethod
    def parse(raw: bytes) -> "Packet":
        pass
