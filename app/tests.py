import io
import struct
import pytest

from app.models import DNSHeader, DNSFlags


@pytest.fixture()
def simple_dns_buffer():
    return b"\x13\x8b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"


@pytest.fixture()
def compressed_dns_buffer():
    return b'`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8"'


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
