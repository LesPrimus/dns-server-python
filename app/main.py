import socket

from app.models import DNSHeader, DNSFlags, DNSQuestion, Reader
from app.models.packet import DNSPacket


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            reader = Reader(buf)

            # Parse request header
            request_header = DNSHeader.from_bytes(reader)

            # Parse question

            request_question = DNSQuestion.from_bytes(reader)

            # Create response header
            response_header = DNSHeader(
                id=request_header.id,
                flags=1 << 15,  # Use proper flags
                question_count=1,
                answer_count=0,
                authority_count=0,
                additional_count=0,
            )

            # Parse questions from request


            # Create packet with header and questions
            packet = DNSPacket(
                header=response_header,
                questions=[request_question],

            )

            udp_socket.sendto(packet.as_bytes, source)
            
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()