import io
import socket

from app.models import DNSHeader, DNSRecord, DNSQuestion, DNSFlags
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

            flags = DNSFlags.from_int(header.flags)
            flags.qr = 1
            flags.rcode = 0 if flags.opcode == 0 else 4


            header.flags = flags.as_int

            # Question
            questions = [
                DNSQuestion.from_bytes(reader) for _ in range(header.question_count)
            ]

            # Answer
            # todo finish me.
            answer = DNSRecord(name=b"\xc0\x0c", type_=1, class_=1, ttl=60, data=b"\x01\x02\x03\x04")


            packet = DNSPacket(
                header,
                questions,
                [answer]
            )



            response = packet.as_bytes

            udp_socket.sendto(response, source)
            
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()