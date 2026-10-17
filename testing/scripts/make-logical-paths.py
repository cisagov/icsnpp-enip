"""Generate a small, deterministic ENIP trace for logical path decoding."""

import struct
import sys


def path(width, values):
    """Encode class, instance and attribute logical segments."""
    result = b""
    for kind, value in zip((0x20, 0x24, 0x30), values):
        if width == 8:
            result += bytes((kind, value))
        else:
            result += bytes((kind + (1 if width == 16 else 2), 0))
            result += struct.pack("<H" if width == 16 else "<I", value)
    return result


def request(width, values):
    encoded = path(width, values)
    return bytes((0x0e, len(encoded) // 2)) + encoded


def enip(cip):
    cpf = struct.pack("<IHHHHHH", 0, 0, 2, 0, 0, 0xb2, len(cip)) + cip
    return struct.pack("<HHII8sI", 0x6f, len(cpf), 1, 0, b"\0" * 8, 0) + cpf


def packet(payload, seq=1, flags=0x18, reverse=False):
    src, dst = (b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02")
    sport, dport = 40000, 44818
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    ethernet = b"\x00" * 12 + b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0, 64, 6, 0, src, dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 1, 0x50, flags, 65535, 0, 0)
    return ethernet + ip + tcp + payload


requests = [
    request(8, (0x12, 0x34, 0x56)),
    request(16, (0x1234, 0x5678, 0x9abc)),
    request(32, (0x12345678, 0x89abcdef, 0xfedcba98)),
]
# Distinct instances previously collided (0x10000 decoded as 0x2000).
inner = [
    requests[0], requests[1], requests[2],
    request(32, (1, 0x10000, 1)),
    request(32, (1, 0x2000, 1)),
    request(32, (1, 0x10000, 1)),
]
offset = 2 + 2 * len(inner)
offsets = []
for item in inner:
    offsets.append(offset)
    offset += len(item)
multiple = b"\x0a\x02\x20\x02\x24\x01" + struct.pack("<H", len(inner))
multiple += struct.pack("<" + "H" * len(offsets), *offsets) + b"".join(inner)
requests.append(multiple)

with open(sys.argv[1], "wb") as output:
    output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    packets = [packet(b"", 0, 0x02), packet(b"", 0, 0x12, True), packet(b"", 1, 0x10)]
    sequence = 1
    for cip in requests:
        payload = enip(cip)
        packets.append(packet(payload, sequence))
        sequence += len(payload)
    for index, frame in enumerate(packets):
        output.write(struct.pack("<IIII", 1700000000 + index, 0, len(frame), len(frame)))
        output.write(frame)
