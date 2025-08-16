import socket

from app.models import DNSHeader, DNSFlags, DNSQuestion, DNSAnswer


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            # HEADER
            request_header = DNSHeader.from_bytes(buf)
            request_flags = DNSFlags.from_bytes(buf)

            response_flags = DNSFlags(
                qr=1,
                opcode=request_flags.opcode,
                aa=0,
                tc=0,
                rd=request_flags.rd,
                ra=1,
                z=0,
                rcode=0 if request_flags.opcode == 0 else 4,
            )
            response_header = DNSHeader(
                id=request_header.id,
                flags=response_flags.as_int,
                question_count=request_header.question_count,
                answer_count=request_header.question_count,
                authority_count=0,
                additional_count=request_header.additional_count,
            )

            response = response_header.as_bytes
            answers = []

            # QUESTIONS

            request_questions = DNSQuestion.from_bytes(buf, qdcount=request_header.question_count)

            for request_question in request_questions:
                response += request_question.as_bytes
                answers.append(DNSAnswer(
                    name=request_question.name,
                    qtype=1,
                    qclass=1,
                    ttl=60,
                    rdata_length=4,
                    rdata="8.8.8.8",
                ))

            for answer in answers:
                response += answer.as_bytes





            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()