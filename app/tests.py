import io
import struct
import pytest

from app.models import DNSHeader, DNSFlags
from app.models.headers import DNSHeaderError
from app.models.questions import DNSQuestion


@pytest.fixture()
def simple_dns_buffer():
    return b"\x13\x8b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"


@pytest.fixture()
def compressed_dns_buffer():
    return b'`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8"'

@pytest.fixture()
def compressed_questions_payload():
    """
    Creates a DNS payload with multiple questions using name compression.
    First question: www.example.com
    Second question: mail.example.com (compressed pointer to "example.com")
    """
    # DNS Header: ID=0x1234, flags=0x0100, QDCOUNT=2, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!6H", 0x1234, 0x0100, 2, 0, 0, 0)

    # First question: www.example.com A IN
    first_question = (
        b"\x03www"  # length=3, "www"
        b"\x07example"  # length=7, "example"
        b"\x03com"  # length=3, "com"
        b"\x00"  # null terminator
        b"\x00\x01"  # QTYPE = A (1)
        b"\x00\x01"  # QCLASS = IN (1)
    )

    # Second question: mail.example.com A IN (using compression)
    second_question = (
        b"\x04mail"  # length=4, "mail"
        b"\xc0\x10"  # compression pointer to offset 0x10 (where "example" starts in first question)
        b"\x00\x01"  # QTYPE = A (1)
        b"\x00\x01"  # QCLASS = IN (1)
    )

    return header + first_question + second_question


class TestDNSHeader:
    def test_header_from_bytes(self):
        buffer = struct.pack(
            "!6H",
            id_ := 123,
            flags := 256,
            question_count := 1,
            answers_count := 1,
            authority_count := 1,
            additional_count := 1,
        )
        buffer = io.BytesIO(buffer)
        header = DNSHeader.from_bytes(buffer)
        assert header.id == id_
        assert header.flags == DNSFlags.from_int(flags)
        assert header.question_count == question_count
        assert header.answer_count == answers_count
        assert header.authority_count == authority_count
        assert header.additional_count == additional_count

    def test_as_bytes(self):
        buffer = struct.pack(
            "!6H",
            id_ := 123,
            flags := 256,
            question_count := 1,
            answers_count := 1,
            authority_count := 1,
            additional_count := 1,
        )
        buffer = io.BytesIO(buffer)
        header = DNSHeader.from_bytes(buffer)
        assert header.as_bytes == buffer.getvalue()

    def test_from_bytes_malformed_header(self):
        # Create a truncated buffer (less than required 12 bytes for DNS header)
        truncated_buffer = struct.pack(
            "!3H",  # Only pack 3 fields instead of 6
            123,  # id
            256,  # flags
            1,  # question_count
        )
        buffer = io.BytesIO(truncated_buffer)

        with pytest.raises(DNSHeaderError, match="Error parsing DNS header"):
            DNSHeader.from_bytes(buffer)

    def test_as_bytes_with_large_values(self):
        header = DNSHeader(
            id=65536,  # Exceeds 16-bit unsigned int
            flags=DNSFlags(qr=0, opcode=0, aa=0, tc=0, rd=0, ra=0, z=0, rcode=0),
            question_count=1,
            answer_count=1,
            authority_count=1,
            additional_count=1,
        )
        with pytest.raises(DNSHeaderError, match="Error building DNS header"):
            _ = header.as_bytes


class TestDNSQuestion:
    def test_from_bytes(self):
        buffer = io.BytesIO(b"\x0ccodecrafters\x02io\x00\x00\x01\x00\x01")
        question = DNSQuestion.from_bytes(buffer)
        assert question.name == b"codecrafters.io"
        assert question.qtype == 1
        assert question.qclass == 1

    def test_as_bytes(self):
        question = DNSQuestion(
            name=b"codecrafters.io",
            qtype=1,
            qclass=1,
        )
        assert question.as_bytes == b"\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"
