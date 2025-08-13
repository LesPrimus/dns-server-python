import socket
import struct
from dataclasses import dataclass, astuple

@dataclass(frozen=True)
class DNSHeader:
    id: int
    flags: int
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int

    @property
    def as_bytes(self):
        return struct.pack("!HHHHHH", *astuple(self))

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            response = DNSHeader(
                id=1234,
                flags=0x8180,
                question_count=0,
                answer_count=0,
                authority_count=0,
                additional_count=0,
            ).as_bytes

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
