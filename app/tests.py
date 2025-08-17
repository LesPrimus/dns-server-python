import pytest

from app.models import DNSHeader, DNSQuestion
from app.models.packet import DNSPacket


@pytest.fixture()
def simple_dns_response():
    from app.models import Reader
    buffer =  b'\x13\x8b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0ccodecrafters\x02io\x00\x00\x01\x00\x01'
    return Reader(buffer)

@pytest.fixture()
def compressed_dns_response():
    from app.models import Reader
    buffer = b'`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8"'
    return Reader(buffer)

class TestDNSHeader:
    def test_from_bytes_simple_dns_response(self, simple_dns_response):
        header = DNSHeader.from_bytes(simple_dns_response)
        assert header.id == 5003
        assert header.flags == 256
        assert header.question_count == 1
        assert header.answer_count == 0
        assert header.authority_count == 0
        assert header.additional_count == 0

    def test_from_bytes_compressed_dns_response(self, compressed_dns_response):
        header = DNSHeader.from_bytes(compressed_dns_response)
        assert header.id == 24662
        assert header.flags == 33152
        assert header.question_count == 1
        assert header.answer_count == 1
        assert header.authority_count == 0
        assert header.additional_count == 0

class TestDNSQuestion:
    def test_as_bytes_simple_dns_response(self, simple_dns_response):
        simple_dns_response.read(12)
        question = DNSQuestion.from_bytes(simple_dns_response)
        assert question.as_bytes == b'\x0ccodecrafters\x02io\x00\x00\x01\x00\x01'

class TestDNSPacket:
    def test_from_bytes_simple_dns_response(self, simple_dns_response):
        request_header = DNSHeader.from_bytes(simple_dns_response)

        response_header = DNSHeader(
            id=request_header.id,
            flags=1 << 15,  # QR - response
            question_count=request_header.question_count,
            answer_count=request_header.question_count,
            authority_count=request_header.authority_count,
            additional_count=request_header.additional_count,

        )

        packet = DNSPacket(
            header=response_header,
            questions=[DNSQuestion.from_bytes(simple_dns_response) for _ in range(request_header.question_count)],
        )

        print(packet.as_bytes)
        assert 0