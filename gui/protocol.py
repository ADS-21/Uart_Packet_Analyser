"""Pure-Python protocol helpers for the ESP32 passive UART analyzer.

The captured frame is a CUSTOM UART application protocol, not TCP/UDP.
IPv4/TCP/UDP will be reported only for an actual embedded IPv4 datagram
with a valid IPv4 header checksum and matching total length.
"""
from __future__ import annotations

FRAME_TYPES = {1: 'DATA', 2: 'ACK', 3: 'CONTROL', 4: 'STATUS', 5: 'CTRL_ACK'}


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    total = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def decode_ip(payload: bytes) -> dict | None:
    """Best-effort *strict* IPv4-in-payload detection (no fabricated TCP/UDP)."""
    if len(payload) < 20 or payload[0] >> 4 != 4:
        return None
    ihl = (payload[0] & 0x0F) * 4
    if ihl < 20 or ihl > len(payload):
        return None
    total = int.from_bytes(payload[2:4], 'big')
    if total < ihl or total != len(payload):
        return None
    if checksum16(payload[:ihl]) != 0:
        return None
    proto = payload[9]
    name = {6: 'TCP', 17: 'UDP'}.get(proto, f'IP protocol {proto}')
    result = {
        'network': 'IPv4', 'transport': name,
        'src_ip': '.'.join(map(str, payload[12:16])),
        'dst_ip': '.'.join(map(str, payload[16:20])),
        'ip_total_length': total,
    }
    offset = (int.from_bytes(payload[6:8], 'big') & 0x1FFF)
    if offset == 0 and proto in (6, 17) and len(payload) >= ihl + 8:
        result['src_port'] = int.from_bytes(payload[ihl:ihl + 2], 'big')
        result['dst_port'] = int.from_bytes(payload[ihl + 2:ihl + 4], 'big')
    return result


def decode_hex(hex_string: str) -> dict:
    if not hex_string:
        raise ValueError('No raw capture available for this event')
    try:
        raw = bytes.fromhex(hex_string)
    except ValueError as exc:
        raise ValueError('Malformed hexadecimal capture') from exc
    if len(raw) < 10:
        raise ValueError('Incomplete frame (minimum 10 bytes)')
    length = int.from_bytes(raw[5:7], 'little')
    if length > 256 or len(raw) != 10 + length:
        raise ValueError(f'Invalid frame length (header={length}, captured={len(raw)})')
    sequence = int.from_bytes(raw[3:5], 'little')
    supplied = int.from_bytes(raw[-3:-1], 'little')
    computed = crc16(raw[1:-3])
    node = raw[1]
    typ = raw[2]
    payload = raw[7:-3]
    return {
        'start': raw[0], 'end': raw[-1], 'node': node, 'destination': 3 - node if node in (1, 2) else None,
        'frame_type': FRAME_TYPES.get(typ & 15, 'UNKNOWN'), 'type_byte': typ,
        'sequence': sequence, 'payload_length': length, 'frame_bytes': len(raw),
        'crc_received': supplied, 'crc_calculated': computed,
        'crc_ok': computed == supplied, 'markers_ok': raw[0] == 0xAA and raw[-1] == 0x55,
        'payload_hex': payload.hex(' ').upper(),
        'payload_ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload),
        'raw_hex': raw.hex(' ').upper(), 'embedded_ip': decode_ip(payload),
    }


def make_frame(source: int, kind: int, sequence: int, payload: bytes = b'') -> bytes:
    if source not in (1, 2) or kind not in FRAME_TYPES or len(payload) > 256:
        raise ValueError('Invalid frame values')
    header = bytes([source, (source << 4) | kind]) + sequence.to_bytes(2, 'little') + len(payload).to_bytes(2, 'little')
    crc = crc16(header + payload)
    return b'\xAA' + header + payload + crc.to_bytes(2, 'little') + b'\x55'
