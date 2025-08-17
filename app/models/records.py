import struct
from dataclasses import dataclass

__all__ = ["DNSRecord"]

from app.utils import decode_name


@dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes

    @classmethod
    def parse_record(cls, reader):
        name = decode_name(reader)
        # the the type, class, TTL, and data length together are 10 bytes (2 + 2 + 4 + 2 = 10)
        # so we read 10 bytes
        data = reader.read(10)
        # HHIH means 2-byte int, 2-byte-int, 4-byte int, 2-byte int
        type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
        data = reader.read(data_len)
        return DNSRecord(name, type_, class_, ttl, data)