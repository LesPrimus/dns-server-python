import struct
from dataclasses import dataclass

__all__ = ["DNSAnswer"]

@dataclass(frozen=True)
class DNSAnswer:
    name: str
    qtype: int
    qclass: int
    ttl: int
    rdata_length: int
    rdata: str

    @property
    def encoded_name(self):
        encoded = b""
        for part in self.name.split("."):
            encoded += bytes([len(part)]) + part.encode()
        return encoded + b"\x00"

    @property
    def encoded_rdata(self):
        parts = [int(x) for x in self.rdata.split(".")]
        return struct.pack("!BBBB", *parts)

    @property
    def as_bytes(self):

        return (
                self.encoded_name
                + struct.pack("!H", self.qtype)
                + struct.pack("!H", self.qclass)
                + struct.pack("!I", self.ttl)
                + struct.pack("!H", self.rdata_length)
                + self.encoded_rdata
        )