import dataclasses
import struct
from io import BytesIO

import pytest

from app.models import DNSQuestion

@dataclasses.dataclass
class Question:
    name: bytes
    type: int
    class_: int

buffer1 =  b'\x13\x8b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01'
buffer2 =  b'\x92\xd3\x01\x00\x00\x02\x00\x00\x00\x00\x00\x00\x03abc\x11longassdomainname\x03com\x00\x00\x01\x00\x01\x03def\xc0\x10\x00\x01\x00\x01'

def parse_question(buf, qdcount=1):
    """Parse questions from DNS packet, handling multiple questions and compression"""
    questions = []
    offset = 12  # Start after header

    # Parse each question based on qdcount from header
    # header = parse_header(buf)

    for _ in range(qdcount):

        # Parse domain name
        name_bytes, new_offset = parse_domain_name(buf, offset)
        question_name = name_bytes
        offset = new_offset

        # Parse type and class (4 bytes total)
        question_type, question_class_ = struct.unpack("!HH", buf[offset : offset + 4])
        offset += 4

        questions.append(Question(question_name, question_type, question_class_))

    return questions

def parse_domain_name(buf, offset):
    """Parse a domain name, handling compression pointers"""
    name_parts = []
    original_offset = offset
    jumped = False

    while offset < len(buf):
        length = buf[offset]

        # Check for compression pointer (top 2 bits set)
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
                jumped = True
            # Extract pointer (bottom 14 bits)
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            offset = pointer
            continue

        # End of name
        if length == 0:
            offset += 1
            break

        # Regular label
        offset += 1
        label = buf[offset : offset + length]
        name_parts.append(bytes([length]) + label)
        offset += length

    # Reconstruct the name with length prefixes and null terminator
    name_bytes = b"".join(name_parts) + b"\x00"

    return name_bytes, original_offset if jumped else offset

def test_some():
    results = DNSQuestion.from_bytes(buffer2, qdcount=2)
    print(results)
    assert 0
