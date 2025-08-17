from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models import Reader

def decode_name(reader: "Reader"):
    parts = []

    while (length := reader.read(1)[0]) != 0:
        if length & 0xC0 == 0xC0:
            parts.append(decode_compressed_name(reader, length))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)

def decode_compressed_name(reader: "Reader", length):
    raise

def encode_dns_name(domain_name):
    encoded = b""
    for part in domain_name.split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"