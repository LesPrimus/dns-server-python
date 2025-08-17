import io
import socket

from app.models import DNSHeader, DNSRecord, DNSQuestion
from app.models.packet import DNSPacket


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            reader = io.BytesIO(buf)

            # Header
            header = DNSHeader.from_bytes(reader)
            header.flags = 1 << 15 | 1 << 8  # Sets QR=1, OPCODE=0, RD=1


            # Question
            question = DNSQuestion.from_bytes(reader)

            # Answer
            answer = DNSRecord(name=b"\xc0\x0c", type_=1, class_=1, ttl=60, data=b"\x01\x02\x03\x04")


            packet = DNSPacket(
                header,
                [question],
                [answer]
            )



            response = packet.as_bytes

            udp_socket.sendto(response, source)
            
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()