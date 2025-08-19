import io
import socket

from app.models import DNSHeader, DNSRecord, DNSQuestion, DNSFlags
from app.models.packet import DNSPacket
from app.utils import get_args, get_resolver_socket, query_resolver


def main():
    resolver = get_args().resolver
    resolver_socket = None
    if resolver:
        forward_host, forward_port = resolver.split(":")
        forward_port = int(forward_port)
        resolver_socket = get_resolver_socket(forward_host, forward_port)

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
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

            if resolver_socket:
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
                    _, answers = query_resolver(resolver_socket, resolver_packet.as_bytes)
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

            udp_socket.sendto(response, source)
            
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()