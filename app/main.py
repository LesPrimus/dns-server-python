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

    @classmethod
    def from_bytes(cls, buf):
        return cls(*struct.unpack("!6H", buf[:12]))

    @property
    def as_bytes(self):
        return struct.pack("!HHHHHH", *astuple(self))


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            request_header = DNSHeader.from_bytes(buf)

            response_header = DNSHeader(
                id=request_header.id,
                flags=0x8180,
                question_count=request_header.question_count,
                answer_count=request_header.answer_count,
                authority_count=request_header.authority_count,
                additional_count=request_header.additional_count,
            )


            udp_socket.sendto(response_header.as_bytes, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
