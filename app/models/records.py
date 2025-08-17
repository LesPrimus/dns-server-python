import struct
from dataclasses import dataclass

__all__ = ["DNSRecord"]

from app.utils import decode_name, encode_ipv4


@dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: str

    @property
    def as_bytes(self):
        rdlength = len(self.data.split("."))
        return (
                self.name
                + struct.pack(">H", self.type_)
                + struct.pack(">H", self.class_)
                + struct.pack(">I", self.ttl)
                + struct.pack(">H", rdlength)
                + encode_ipv4(self.data)
        )