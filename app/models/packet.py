from dataclasses import dataclass, field

from app.models import DNSHeader, DNSQuestion, DNSRecord

__all__ = ["DNSPacket"]


@dataclass
class DNSPacket:
    header: DNSHeader
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSRecord] = field(default_factory=list)
    # authorities: list[DNSRecord]
    # additionals: list[DNSRecord]

    @property
    def as_bytes(self):
        header = self.header
        if self.questions:
            header.question_count = len(self.questions)
        if self.answers:
            header.answer_count = len(self.answers)
        result = header.as_bytes
        for question in self.questions:
            result += question.as_bytes
        for answer in self.answers:
            result += answer.as_bytes
        return result
