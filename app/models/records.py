import io
import struct
from dataclasses import dataclass

__all__ = ["DNSRecord"]

from app.utils import encode_ipv4, encode_dns_name, decode_name, decode_ipv4


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
                encode_dns_name(self.name)
                + struct.pack(">H", self.type_)
                + struct.pack(">H", self.class_)
                + struct.pack(">I", self.ttl)
                + struct.pack(">H", rdlength)
                + encode_ipv4(self.data)
        )

    @classmethod
    def from_bytes(cls, buffer: io.BytesIO):
        name = decode_name(buffer)
        data = buffer.read(10)
        type_, class_, ttl, rdlength = struct.unpack(">HHLH", data)
        data = buffer.read(rdlength)
        data = decode_ipv4(data)
        return cls(name, type_, class_, ttl, data)