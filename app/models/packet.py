from dataclasses import dataclass, field

from app.models import DNSHeader, DNSQuestion, DNSRecord, Reader

__all__ = ["DNSPacket"]

@dataclass
class DNSPacket:
    header: DNSHeader
    questions: list[DNSQuestion]
    # questions: list[DNSQuestion]
    # records: list[DNSRecord]
    # authorities: list[DNSRecord]
    # additionals: list[DNSRecord]

    @property
    def as_bytes(self):
        result = self.header.as_bytes
        for question in self.questions:
            result += question.as_bytes
        return result

