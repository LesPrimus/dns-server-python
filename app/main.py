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

@dataclass(frozen=True)
class DNSQuestion:
    name: str
    qtype: int
    qclass: int


    @classmethod
    def _decode_dns_name(cls, data):
        parts = []
        offset = 0
        while True:
            length = data[offset]
            if length == 0:
                break
            offset += 1
            parts.append(data[offset:offset + length].decode())
            offset += length
        name =  ".".join(parts)
        return name, offset + 1

    @classmethod
    def parse_dns_question(cls, data, offset=12):
        # Parse the domain name starting from offset
        name, name_end_offset = cls._decode_dns_name(data[offset:])

        # Calculate absolute offset for type and class
        type_class_offset = offset + name_end_offset

        # Unpack type and class (each 2 bytes, big-endian)
        dns_type, dns_class = struct.unpack("!HH", data[type_class_offset:type_class_offset + 4])

        return name, dns_type, dns_class

    @classmethod
    def from_bytes(cls, buf):
        name, qtype, qclass = cls.parse_dns_question(buf)
        return cls(name, qtype, qclass)

    @property
    def encoded_name(self):
        encoded = b""
        for part in self.name.split("."):
            encoded += bytes([len(part)]) + part.encode()
        return encoded + b"\x00"


    @property
    def as_bytes(self):
        return self.encoded_name + struct.pack("!HH", self.qtype, self.qclass)


@dataclass(frozen=True)
class DNSAnswer:
    name: str
    qtype: int
    qclass: int
    ttl: int
    rdata_length: int
    rdata: str

    @property
    def encoded_name(self):
        encoded = b""
        for part in self.name.split("."):
            encoded += bytes([len(part)]) + part.encode()
        return encoded + b"\x00"

    @property
    def encoded_rdata(self):
        parts = [int(x) for x in self.rdata.split(".")]
        return struct.pack("!BBBB", *parts)

    @property
    def as_bytes(self):

        return (
                self.encoded_name
                + struct.pack("!H", self.qtype)
                + struct.pack("!H", self.qclass)
                + struct.pack("!I", self.ttl)
                + struct.pack("!H", self.rdata_length)
                + self.encoded_rdata
        )


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
                question_count=1,
                answer_count=1,
                authority_count=0,
                additional_count=request_header.additional_count,
            )

            request_question = DNSQuestion.from_bytes(buf)
            response_answer = DNSAnswer(
                name=request_question.name,
                qtype=1,
                qclass=1,
                ttl=60,
                rdata_length=4,
                rdata="8.8.8.8",
            )

            response = response_header.as_bytes + request_question.as_bytes + response_answer.as_bytes


            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
