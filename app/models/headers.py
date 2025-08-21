import io
import struct
from dataclasses import astuple, dataclass
from typing import Self


__all__ = ["DNSHeader", "DNSFlags"]


@dataclass
class DNSFlags:
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int

    @classmethod
    def from_int(cls, flags: int) -> Self:
        # Extract 16-bit flags value from buffer (bytes 2-4 in DNS header)

        return cls(
            qr=(flags >> 15) & 0x1,  # bit 15
            opcode=(flags >> 11) & 0xF,  # bits 11-14
            aa=(flags >> 10) & 0x1,  # bit 10
            tc=(flags >> 9) & 0x1,  # bit 9
            rd=(flags >> 8) & 0x1,  # bit 8
            ra=(flags >> 7) & 0x1,  # bit 7
            z=(flags >> 4) & 0x7,  # bits 4-6
            rcode=flags & 0xF,  # bits 0-3
        )

    @property
    def as_int(self) -> int:
        # Build 16-bit flags value by shifting bits to correct positions
        return (
            (self.qr & 0x1) << 15  # QR - 1 bit
            | (self.opcode & 0xF) << 11  # OPCODE - 4 bits
            | (self.aa & 0x1) << 10  # AA - 1 bit
            | (self.tc & 0x1) << 9  # TC - 1 bit
            | (self.rd & 0x1) << 8  # RD - 1 bit
            | (self.ra & 0x1) << 7  # RA - 1 bit
            | (self.z & 0x7) << 4  # Z - 3 bits
            | (self.rcode & 0xF)  # RCODE - 4 bits
        )


@dataclass
class DNSHeader:
    id: int
    flags: DNSFlags
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int

    @classmethod
    def from_bytes(cls, reader: io.BytesIO) -> Self:
        (
            id_,
            flags,
            question_count,
            answers_count,
            authority_count,
            additional_count,
        ) = struct.unpack("!6H", reader.read(12))
        flags = DNSFlags.from_int(flags)

        return cls(
            id_, flags, question_count, answers_count, authority_count, additional_count
        )

    @property
    def as_bytes(self):
        return struct.pack(
            "!6H",
            self.id,
            self.flags.as_int,
            self.question_count,
            self.answer_count,
            self.authority_count,
            self.additional_count,
        )
