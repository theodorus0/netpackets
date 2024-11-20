from abc import abstractmethod
from typing import Optional


class Packet:
    @abstractmethod
    def build(self) -> bytes:
        pass

    @staticmethod
    @abstractmethod
    def parse(raw: bytes) -> "Packet":
        pass

    @property
    def sublayer(self) -> Optional["Packet"]:
        pass
