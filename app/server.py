import io
import socket
from collections.abc import Iterable

from app.models import DNSHeader, DNSFlags, DNSQuestion, DNSRecord
from app.models.packet import DNSPacket
from app.utils import get_resolver_socket, query_resolver


class Server:
    DEFAULT_TTL = 60  # sec.
    DEFAULT_DATA = "1.2.3.4"
    DNS_BUFFER_SIZE = 512

    def __init__(self, host: str, port: int, *, resolver: str = None):
        self.host = host
        self.port = port
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((host, port))
        self.resolver_socket = get_resolver_socket(resolver) if resolver else None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @staticmethod
    def get_header(reader: io.BytesIO) -> DNSHeader:
        header = DNSHeader.from_bytes(reader)
        header.flags.qr = 1
        header.flags.rcode = 0 if header.flags.opcode == 0 else 4
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
            flags=DNSFlags.from_int(0),
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
                    ttl=self.DEFAULT_TTL,
                    data=self.DEFAULT_DATA,
                )
                for question in questions
            ]

    def handle_request(self):
        buf, source = self.udp_socket.recvfrom(self.DNS_BUFFER_SIZE)
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

    def close(self):
        self.udp_socket.close()
        if self.resolver_socket:
            self.resolver_socket.close()
