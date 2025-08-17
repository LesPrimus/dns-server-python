import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from app.utils import decode_name, encode_dns_name

if TYPE_CHECKING:
    from app.models import Reader

__all__ = ["DNSQuestion"]


@dataclass(frozen=True)
class DNSQuestion:
    name: bytes
    qtype: int
    qclass: int


    @classmethod
    def from_bytes(cls, reader: "Reader"):
        name = decode_name(reader)
        data = reader.read(4)
        type_, class_ = struct.unpack("!HH", data)
        return cls(name, type_, class_)

    @property
    def as_bytes(self):
        return encode_dns_name(self.name) + struct.pack("!HH", self.qtype, self.qclass)