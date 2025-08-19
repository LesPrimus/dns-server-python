import argparse
import io
import struct
import socket


def decode_name(reader: io.BytesIO):
    parts = []

    while (length := reader.read(1)[0]) != 0:
        if length & 0xC0 == 0xC0:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)


def decode_compressed_name(length, reader):
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result


def encode_dns_name(domain_name):
    encoded = b""
    for part in domain_name.split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"


def encode_ipv4(ip):
    return struct.pack("!BBBB", *map(int, ip.split(".")))


def decode_ipv4(data):
    return ".".join(map(str, struct.unpack("!BBBB", data)))


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolver", type=str)
    return parser.parse_args()


def get_resolver_socket(host_and_port: str):
    forward_host, forward_port = host_and_port.split(":")
    forward_port = int(forward_port)
    resolver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    resolver_socket.connect((forward_host, forward_port))
    return resolver_socket


def query_resolver(resolver_socket, query):
    from app.models import DNSHeader, DNSQuestion, DNSRecord

    resolver_socket.send(query)
    buffer, _ = resolver_socket.recvfrom(512)
    reader = io.BytesIO(buffer)
    header = DNSHeader.from_bytes(reader)
    questions = [DNSQuestion.from_bytes(reader) for _ in range(header.question_count)]
    answers = [DNSRecord.from_bytes(reader) for _ in range(header.answer_count)]
    return questions, answers
