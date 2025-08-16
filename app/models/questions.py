import struct
from dataclasses import dataclass

__all__ = ["DNSQuestion"]


@dataclass(frozen=True)
class DNSQuestion:
    name: bytes
    qtype: int
    qclass: int

    @classmethod
    def parse_question(cls, buf, qdcount=1):
        """Parse questions from DNS packet, handling multiple questions and compression"""
        questions = []
        offset = 12  # Start after header

        for _ in range(qdcount):
            # Parse domain name
            name_bytes, new_offset = cls.parse_domain_name(buf, offset)
            question_name = name_bytes
            offset = new_offset

            # Parse type and class (4 bytes total)
            question_type, question_class_ = struct.unpack("!HH", buf[offset: offset + 4])
            offset += 4

            questions.append(cls(question_name, question_type, question_class_))

        return questions

    @classmethod
    def parse_domain_name(cls, buf, offset):
        name_parts = []
        original_offset = offset
        jumped = False

        while offset < len(buf):
            length = buf[offset]

            # Check for compression:
            if (length & 0xC0) == 0xC0:
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                # Extract pointer (bottom 14 bits)
                pointer = ((length & 0x3F) << 8) | buf[offset + 1]
                offset = pointer
                continue

            # End of name
            if length == 0:
                offset += 1
                break

            # Regular label
            offset += 1
            label = buf[offset: offset + length]
            name_parts.append(bytes([length]) + label)
            offset += length

        # Reconstruct the name with length prefixes and null terminator
        name_bytes = b"".join(name_parts) + b"\x00"

        return name_bytes, original_offset if jumped else offset

    @classmethod
    def from_bytes(cls, buf, *, qdcount=1) -> list["DNSQuestion"]:
        return cls.parse_question(buf, qdcount=qdcount)

    @property
    def encoded_name(self):
        encoded = b""
        for part in self.name.split("."):
            encoded += bytes([len(part)]) + part.encode()
        return encoded + b"\x00"


    @property
    def as_bytes(self):
        return self.name + struct.pack("!HH", self.qtype, self.qclass)