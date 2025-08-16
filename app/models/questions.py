import struct
from dataclasses import dataclass

__all__ = ["DNSQuestion"]

@dataclass(frozen=True)
class DNSQuestion:
    name: str
    qtype: int
    qclass: int


    @classmethod
    def _decode_dns_name(cls, data):
        parts = []
        offset = 0
        while True:
            length = data[offset]
            if length == 0:
                break
            offset += 1
            parts.append(data[offset:offset + length].decode())
            offset += length
        name =  ".".join(parts)
        return name, offset + 1

    @classmethod
    def parse_dns_question(cls, data, offset=12):
        # Parse the domain name starting from offset
        name, name_end_offset = cls._decode_dns_name(data[offset:])

        # Calculate absolute offset for type and class
        type_class_offset = offset + name_end_offset

        # Unpack type and class (each 2 bytes, big-endian)
        dns_type, dns_class = struct.unpack("!HH", data[type_class_offset:type_class_offset + 4])

        return name, dns_type, dns_class

    @classmethod
    def from_bytes(cls, buf):
        name, qtype, qclass = cls.parse_dns_question(buf)
        return cls(name, qtype, qclass)

    @property
    def encoded_name(self):
        encoded = b""
        for part in self.name.split("."):
            encoded += bytes([len(part)]) + part.encode()
        return encoded + b"\x00"


    @property
    def as_bytes(self):
        return self.encoded_name + struct.pack("!HH", self.qtype, self.qclass)