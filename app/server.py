import io
import socket

from app.models import DNSHeader, DNSFlags, DNSQuestion, DNSRecord
from app.models.packet import DNSPacket
from app.utils import get_resolver_socket, query_resolver


class Server:
    def __init__(self, host: str, port: int, *, resolver: str = None):
        self.host = host
        self.port = port
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind(("127.0.0.1", 2053))
        self.resolver_socket = get_resolver_socket(resolver) if resolver else None

    def handle_request(self):
        buf, source = self.udp_socket.recvfrom(512)
        reader = io.BytesIO(buf)

        # Header
        header = DNSHeader.from_bytes(reader)

        flags = DNSFlags.from_int(header.flags)
        flags.qr = 1
        flags.rcode = 0 if flags.opcode == 0 else 4


        header.flags = flags.as_int

        # Questions and answers
        questions, answers = [], []
        for _ in range(header.question_count):
            question = DNSQuestion.from_bytes(reader)
            questions.append(question)

        if self.resolver_socket:
            for question in questions:
                resolver_header = DNSHeader(
                    id=header.id,
                    flags=0,
                    question_count=1,
                    answer_count=0,
                    authority_count=0,
                    additional_count=0
                )
                resolver_packet = DNSPacket(
                    resolver_header,
                    [question]
                )
                _, answers = query_resolver(self.resolver_socket, resolver_packet.as_bytes)
                answers.extend(answers)

        else:
            for question in questions:
                answer = DNSRecord(
                    name=question.name,
                    type_=question.qtype,
                    class_=question.qclass,
                    ttl=60,
                    data="1.2.3.4"
                )
                answers.append(answer)

        packet = DNSPacket(
            header,
            questions,
            answers
        )


        response = packet.as_bytes

        self.udp_socket.sendto(response, source)




    def run(self):
        while True:
            try:
                self.handle_request()
            except Exception as e:
                print(f"Error receiving data: {e}")
                break
