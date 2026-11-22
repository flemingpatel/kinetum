# Copyright (c) 2026 Fleming Patel. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Serialize fixed-header IPv4/UDP probes and verify their Internet checksums."""

import ipaddress
import struct

from ..config.types import CONSTANTS, PacketConfig


def internet_checksum(data: bytes) -> int:
    """Return the one's complement of the end-around-carry sum of network-order words."""
    padded = data + (b"\x00" if len(data) % 2 else b"")
    total = sum(word[0] for word in struct.iter_unpack("!H", padded))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return total ^ 0xffff


def ipv4_udp(source_ip: str, destination_ip: str, source_port: int, destination_port: int,
             payload: bytes, *, dscp: int = 0, identification: int = 0, fragment: int = 0x4000) -> bytes:
    """Encode an unfragmented datagram, including independent IPv4 and UDP checksums."""
    source = ipaddress.IPv4Address(source_ip).packed
    destination = ipaddress.IPv4Address(destination_ip).packed
    length = 8 + len(payload)
    udp = struct.pack("!HHHH", source_port, destination_port, length, 0) + payload
    checksum = internet_checksum(source + destination + struct.pack("!BBH", 0, 17, length) + udp)
    udp = udp[:6] + struct.pack("!H", checksum or 0xffff) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, dscp << 2, 20 + length, identification,
                         fragment, 64, 17, 0, source, destination)
    return header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:] + udp


def minimum_frames(packet: PacketConfig, source_mac: str, destination_mac: str, dscp: int = 0) -> list[str]:
    """Serialize the 64 exact untagged flow templates, including both checksums and excluding the FCS."""
    ethernet = bytes.fromhex((destination_mac + source_mac).replace(":", "")) + b"\x08\x00"
    return [
        (ethernet + ipv4_udp(packet.src_ip, packet.dst_ip, packet.base_sport + flow, packet.base_dport,
                             b"KINETUM" + bytes([flow]) + bytes(range(10)), dscp=dscp,
                             identification=1, fragment=0)).hex()
        for flow in range(CONSTANTS.MINIMUM_FRAME_FLOWS)
    ]
