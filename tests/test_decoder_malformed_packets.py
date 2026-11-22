import struct

from src.stream.decoder import PacketStreamDecoder


def ethernet_ipv4(payload: bytes, *, version_ihl: int = 0x45, protocol: int = 17, total_length: int | None = None) -> bytes:
    ethernet = bytearray(14)
    ethernet[12:14] = struct.pack("!H", 0x0800)

    ip_header = bytearray(20)
    ip_header[0] = version_ihl
    ip_header[2:4] = struct.pack("!H", total_length if total_length is not None else 20 + len(payload))
    ip_header[9] = protocol
    ip_header[12:16] = bytes((192, 0, 2, 1))
    ip_header[16:20] = bytes((198, 51, 100, 2))
    return bytes(ethernet + ip_header + payload)


def test_rejects_non_ipv4_version():
    assert PacketStreamDecoder.decode_raw_ethernet(
        ethernet_ipv4(b"\x00" * 8, version_ihl=0x65)
    ) is None


def test_rejects_ipv4_header_length_below_minimum():
    assert PacketStreamDecoder.decode_raw_ethernet(
        ethernet_ipv4(b"\x00" * 8, version_ihl=0x44)
    ) is None


def test_rejects_ipv4_total_length_shorter_than_header():
    assert PacketStreamDecoder.decode_raw_ethernet(
        ethernet_ipv4(b"\x00" * 8, total_length=19)
    ) is None


def test_rejects_truncated_ipv4_packet():
    assert PacketStreamDecoder.decode_raw_ethernet(
        ethernet_ipv4(b"\x00" * 8, total_length=40)
    ) is None


def test_rejects_malformed_udp_length():
    udp_header = struct.pack("!HHHH", 12345, 53, 7, 0)
    assert PacketStreamDecoder.decode_raw_ethernet(
        ethernet_ipv4(udp_header, protocol=17)
    ) is None


def test_uses_ipv4_and_udp_lengths_not_ethernet_padding():
    payload = b"abc"
    udp_header = struct.pack("!HHHH", 12345, 53, 8 + len(payload), 0)
    packet = ethernet_ipv4(udp_header + payload, protocol=17) + b"ethernet-padding"

    decoded = PacketStreamDecoder.decode_raw_ethernet(packet)

    assert decoded is not None
    assert decoded.protocol == "UDP"
    assert decoded.src_port == 12345
    assert decoded.dst_port == 53
    assert decoded.payload == payload
