"""
Real-time packet and event stream decoder with Shannon entropy computation.
"""

import math
import struct
import time
from typing import Dict, Any, Optional, Tuple
from src.stream.events import NetworkPacket


class PacketStreamDecoder:
    """Decodes raw network packets or streaming event dictionaries into structured NetworkPacket instances."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy for packet payload to detect encryption or packing."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        for count in freq:
            if count > 0:
                p_x = float(count) / length
                entropy -= p_x * math.log2(p_x)
        return entropy

    @classmethod
    def decode_raw_ethernet(cls, raw_data: bytes, timestamp: Optional[float] = None) -> Optional[NetworkPacket]:
        """Decode raw Ethernet / IP / TCP or UDP packet bytes."""
        ts = timestamp if timestamp is not None else time.time()
        if len(raw_data) < 14:
            return None

        # Parse Ethernet header
        eth_type = struct.unpack("!H", raw_data[12:14])[0]
        offset = 14

        # 0x0800 is IPv4
        if eth_type != 0x0800:
            return None

        if len(raw_data) < offset + 20:
            return None

        ip_header = raw_data[offset:offset + 20]
        version_ihl = ip_header[0]
        if version_ihl >> 4 != 4:
            return None

        ihl = (version_ihl & 0x0F) * 4
        if ihl < 20 or len(raw_data) < offset + ihl:
            return None

        total_length = struct.unpack("!H", ip_header[2:4])[0]
        if total_length < ihl or total_length > len(raw_data) - offset:
            return None
        packet_end = offset + total_length

        protocol_num = ip_header[9]
        src_ip = ".".join(map(str, ip_header[12:16]))
        dst_ip = ".".join(map(str, ip_header[16:20]))

        offset += ihl
        src_port = 0
        dst_port = 0
        protocol_name = "OTHER"
        tcp_flags = {}

        if protocol_num == 6:  # TCP
            protocol_name = "TCP"
            if packet_end >= offset + 20:
                src_port, dst_port, seq, ack, offset_reserved, flags = struct.unpack("!HHLLBB", raw_data[offset:offset + 14])
                tcp_flags = {
                    "fin": bool(flags & 0x01),
                    "syn": bool(flags & 0x02),
                    "rst": bool(flags & 0x04),
                    "psh": bool(flags & 0x08),
                    "ack": bool(flags & 0x10),
                    "urg": bool(flags & 0x20),
                }
                tcp_header_len = ((offset_reserved >> 4) & 0x0F) * 4
                if tcp_header_len < 20 or packet_end < offset + tcp_header_len:
                    return None
                offset += tcp_header_len
        elif protocol_num == 17:  # UDP
            protocol_name = "UDP"
            if packet_end >= offset + 8:
                src_port, dst_port, length, checksum = struct.unpack("!HHHH", raw_data[offset:offset + 8])
                if length < 8 or length > packet_end - offset:
                    return None
                offset += 8
                packet_end = offset + length
        elif protocol_num == 1:  # ICMP
            protocol_name = "ICMP"
            offset += 8

        payload = raw_data[offset:packet_end]
        entropy = cls.calculate_entropy(payload)

        return NetworkPacket(
            timestamp=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol_name,
            packet_size=len(raw_data),
            tcp_flags=tcp_flags,
            payload_entropy=entropy,
            payload=payload,
        )

    @classmethod
    def decode_dict_event(cls, event: Dict[str, Any]) -> NetworkPacket:
        """Decode structured JSON/dictionary telemetry event."""
        payload_bytes = b""
        if "payload" in event:
            if isinstance(event["payload"], str):
                payload_bytes = event["payload"].encode("utf-8")
            elif isinstance(event["payload"], bytes):
                payload_bytes = event["payload"]

        entropy = event.get("payload_entropy")
        if entropy is None:
            entropy = cls.calculate_entropy(payload_bytes)

        flags = event.get("tcp_flags", {})
        if not isinstance(flags, dict):
            flags = {}

        return NetworkPacket(
            timestamp=float(event.get("timestamp", time.time())),
            src_ip=str(event.get("src_ip", "0.0.0.0")),
            dst_ip=str(event.get("dst_ip", "0.0.0.0")),
            src_port=int(event.get("src_port", 0)),
            dst_port=int(event.get("dst_port", 0)),
            protocol=str(event.get("protocol", "TCP")).upper(),
            packet_size=int(event.get("packet_size", len(payload_bytes))),
            tcp_flags=flags,
            payload_entropy=float(entropy),
            payload=payload_bytes,
        )
