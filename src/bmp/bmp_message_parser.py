"""BMP message parsing for BMP protocol.

This module handles parsing of BMP-specific messages like PEER_UP, PEER_DOWN,
INITIATION, TERMINATION, and STATS_REPORT.
"""

import ipaddress
import logging
import struct
from enum import IntEnum
from typing import Any, Dict, List, Tuple

from .bgp_parser import BGPMessageParser
from .parsing_utils import safe_struct_unpack, validate_data_length

logger = logging.getLogger(__name__)


class BMPMessageType(IntEnum):
    """BMP message types."""

    ROUTE_MONITORING = 0
    STATS_REPORT = 1
    STATISTICS_REPORT = 1  # Alias for backward compatibility
    PEER_DOWN = 2
    PEER_UP = 3
    INITIATION = 4
    TERMINATION = 5
    ROUTE_MIRRORING = 6  # For backward compatibility with tests


class BMPMessageParser:
    """Parser for BMP-specific messages."""

    def __init__(self):
        self.bgp_parser = BGPMessageParser()

    def parse_per_peer_header(self, data: bytes) -> Tuple[Dict[str, Any], int]:
        """Parse per-peer header common to many BMP messages.

        Returns:
            Tuple of (peer_header_dict, offset_after_header)
        """
        validate_data_length(data, 42, "per-peer header")

        header: Dict[str, Any] = {}
        offset = 0

        # Parse per-peer header fields
        header["peer_type"], offset = safe_struct_unpack(">B", data, offset)
        flags_byte, offset = safe_struct_unpack(">B", data, offset)

        # Parse peer flags into a dictionary for backward compatibility
        header["peer_flags"] = {
            "v_flag": bool(flags_byte & 0x80),  # Bit 0 (MSB): IPv6 flag
            "l_flag": bool(flags_byte & 0x40),  # Bit 1: Legacy format flag
            "a_flag": bool(flags_byte & 0x20),  # Bit 2: AS path flag
            "raw": flags_byte,
        }
        header["peer_distinguisher"] = data[offset : offset + 8].hex()
        offset += 8

        # Peer address (16 bytes, can be IPv4 or IPv6)
        peer_addr_data = data[offset : offset + 16]
        offset += 16

        # Check if it's an IPv4 address (last 4 bytes non-zero, first 12 bytes zero)
        if peer_addr_data[:12] == b"\x00" * 12:
            header["peer_ip"] = str(ipaddress.IPv4Address(peer_addr_data[12:16]))
        else:
            # For IPv6 addresses that are IPv4-mapped, extract the IPv4 portion
            try:
                ipv6_addr = ipaddress.IPv6Address(peer_addr_data)
                if ipv6_addr.ipv4_mapped:
                    header["peer_ip"] = str(ipv6_addr.ipv4_mapped)
                else:
                    header["peer_ip"] = str(ipv6_addr)
            except Exception:
                header["peer_ip"] = peer_addr_data.hex()

        # Parse remaining fields
        header["peer_as"], offset = safe_struct_unpack(">I", data, offset)
        header["peer_bgp_id"] = str(ipaddress.IPv4Address(data[offset : offset + 4]))
        offset += 4
        header["timestamp_sec"], offset = safe_struct_unpack(">I", data, offset)
        header["timestamp_usec"], offset = safe_struct_unpack(">I", data, offset)

        return header, offset

    def parse_peer_up(self, data: bytes) -> Dict[str, Any]:
        """Parse PEER_UP message."""
        peer_header, offset = self.parse_per_peer_header(data)

        validate_data_length(data, offset + 20, "PEER_UP message body")

        # Local address (16 bytes)
        local_addr_data = data[offset : offset + 16]
        offset += 16

        # Check if it's IPv4 or IPv6
        if local_addr_data[:12] == b"\x00" * 12:
            local_ip = str(ipaddress.IPv4Address(local_addr_data[12:16]))
        else:
            # For IPv6 addresses that are IPv4-mapped, extract the IPv4 portion
            try:
                ipv6_addr = ipaddress.IPv6Address(local_addr_data)
                if ipv6_addr.ipv4_mapped:
                    local_ip = str(ipv6_addr.ipv4_mapped)
                else:
                    local_ip = str(ipv6_addr)
            except Exception:
                local_ip = local_addr_data.hex()

        # Local and remote ports
        local_port, offset = safe_struct_unpack(">H", data, offset)
        remote_port, offset = safe_struct_unpack(">H", data, offset)

        # Parse sent and received OPEN messages
        sent_open = None
        received_open = None

        if offset < len(data):
            sent_open = self.bgp_parser.parse_bgp_message(data[offset:])
            # For simplicity, assume the rest is received OPEN
            # In practice, you'd need to parse the length to find the boundary

        return {
            "type": "peer_up",
            "peer": peer_header,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_port": remote_port,
            "sent_open_message": sent_open,
            "received_open_message": received_open,
        }

    def parse_peer_down(self, data: bytes) -> Dict[str, Any]:
        """Parse PEER_DOWN message."""
        peer_header, offset = self.parse_per_peer_header(data)

        validate_data_length(data, offset + 1, "PEER_DOWN reason")

        # Reason for peer down
        reason, offset = safe_struct_unpack(">B", data, offset)

        message: Dict[str, Any] = {"type": "peer_down", "peer": peer_header, "reason": reason}

        # Parse additional data based on reason
        if reason == 1 and offset < len(data):
            # Local system closed session with notification
            message["notification"] = self.bgp_parser.parse_bgp_message(data[offset:])
        elif reason == 2 and offset < len(data):
            # Local system closed session without notification, FSM event follows
            message["fsm_event_code"], _ = safe_struct_unpack(">H", data, offset)
        elif reason == 3 and offset < len(data):
            # Remote system closed session with notification
            message["notification"] = self.bgp_parser.parse_bgp_message(data[offset:])

        return message

    def parse_stats_report(self, data: bytes) -> Dict[str, Any]:
        """Parse STATS_REPORT message."""
        peer_header, offset = self.parse_per_peer_header(data)

        validate_data_length(data, offset + 4, "STATS_REPORT count")

        # Number of statistics
        stats_count, offset = safe_struct_unpack(">I", data, offset)

        statistics = []
        for i in range(stats_count):
            if offset + 6 > len(data):
                break

            # Parse stat type and length
            stat_type, offset = safe_struct_unpack(">H", data, offset)
            stat_len, offset = safe_struct_unpack(">H", data, offset)

            if offset + stat_len > len(data):
                break

            # Parse stat data based on type and length
            stat_data = data[offset : offset + stat_len]
            offset += stat_len

            stat_value = self._parse_stat_value(stat_type, stat_data)
            statistics.append({"type": stat_type, "length": stat_len, "value": stat_value})

        return {
            "type": "stats_report",
            "peer": peer_header,
            "statistics_count": stats_count,
            "statistics": statistics,
            "stats": statistics,  # For backward compatibility
        }

    def parse_initiation(self, data: bytes) -> Dict[str, Any]:
        """Parse INITIATION message."""
        message: Dict[str, Any] = {"type": "initiation"}

        # Parse TLVs
        message["information"] = self._parse_tlvs(data)

        return message

    def parse_termination(self, data: bytes) -> Dict[str, Any]:
        """Parse TERMINATION message."""
        message: Dict[str, Any] = {"type": "termination"}

        # Parse TLVs
        message["information"] = self._parse_tlvs(data)

        return message

    def _parse_stat_value(self, stat_type: int, data: bytes) -> Any:
        """Parse statistics value based on type."""
        try:
            if len(data) == 4:
                # 32-bit counter
                return struct.unpack(">I", data)[0]
            elif len(data) == 8:
                # 64-bit counter
                return struct.unpack(">Q", data)[0]
            else:
                # Unknown format, return as hex
                return data.hex()
        except struct.error:
            return data.hex()

    def _parse_tlvs(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse Type-Length-Value fields."""
        tlvs = []
        offset = 0

        while offset + 4 <= len(data):
            try:
                # Parse TLV header
                tlv_type, offset = safe_struct_unpack(">H", data, offset)
                tlv_len, offset = safe_struct_unpack(">H", data, offset)

                if offset + tlv_len > len(data):
                    break

                # Extract TLV data
                tlv_data = data[offset : offset + tlv_len]
                offset += tlv_len

                # Parse based on TLV type
                tlv_value = self._parse_tlv_value(tlv_type, tlv_data)

                tlvs.append({"type": tlv_type, "length": tlv_len, "value": tlv_value})

            except Exception as e:
                logger.warning(f"Error parsing TLV at offset {offset}: {e}")
                break

        return tlvs

    def _parse_tlv_value(self, tlv_type: int, data: bytes) -> str:
        """Parse TLV value based on type."""
        # Common TLV types for INITIATION/TERMINATION
        if tlv_type == 0:  # String
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.hex()
        elif tlv_type == 1:  # System Description
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.hex()
        elif tlv_type == 2:  # System Name
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.hex()
        else:
            # Unknown type, return as hex
            return data.hex()
