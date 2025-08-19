import io
import socket
from collections.abc import Iterable

from app.models import DNSHeader, DNSFlags, DNSQuestion, DNSRecord
from app.models.packet import DNSPacket
from app.utils import get_resolver_socket, query_resolver


class Server:
    default_ttl = 60  # sec.
    default_data = "1.2.3.4"

    def __init__(self, host: str, port: int, *, resolver: str = None):
        self.host = host
        self.port = port
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind(("127.0.0.1", 2053))
        self.resolver_socket = get_resolver_socket(resolver) if resolver else None

    @staticmethod
    def get_header(reader: io.BytesIO) -> DNSHeader:
        header = DNSHeader.from_bytes(reader)
        # Fixme: move to a setter
        flags = DNSFlags.from_int(header.flags)
        flags.qr = 1
        flags.rcode = 0 if flags.opcode == 0 else 4
        header.flags = flags.as_int
        return header

    @staticmethod
    def get_questions(header: DNSHeader, reader: io.BytesIO) -> list[DNSQuestion]:
        return [DNSQuestion.from_bytes(reader) for _ in range(header.question_count)]

    def get_answers_from_resolver(
        self, header: DNSHeader, questions: Iterable[DNSQuestion]
    ) -> list[DNSRecord]:
        resolved_answers = []
        resolver_header = DNSHeader(
            id=header.id,
            flags=0,
            question_count=1,
            answer_count=0,
            authority_count=0,
            additional_count=0,
        )
        for question in questions:
            resolver_packet = DNSPacket(resolver_header, [question])
            (_, [answer]) = query_resolver(
                self.resolver_socket, resolver_packet.as_bytes
            )
            resolved_answers.append(answer)
        return resolved_answers

    def get_answers(
        self, header: DNSHeader, questions: Iterable[DNSQuestion]
    ) -> list[DNSRecord]:
        if self.resolver_socket:
            return self.get_answers_from_resolver(header, questions)
        else:
            return [
                DNSRecord(
                    name=question.name,
                    type_=question.qtype,
                    class_=question.qclass,
                    ttl=self.default_ttl,
                    data=self.default_data,
                )
                for question in questions
            ]

    def handle_request(self):
        buf, source = self.udp_socket.recvfrom(512)
        reader = io.BytesIO(buf)

        header = self.get_header(reader)
        questions = self.get_questions(header, reader)
        answers = self.get_answers(header, questions)

        packet = DNSPacket(header, questions, answers)
        self.udp_socket.sendto(packet.as_bytes, source)

    def run(self):
        while True:
            try:
                self.handle_request()
            except Exception as e:
                print(f"Error receiving data: {e}")
                break
