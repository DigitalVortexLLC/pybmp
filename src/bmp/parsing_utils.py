"""Common parsing utilities for BMP protocol messages.

This module contains reusable parsing functions that eliminate code duplication
and provide consistent parsing behavior across different message types.
"""

import struct
import ipaddress
import logging
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)


class ParseError(Exception):
    """Custom exception for parsing errors."""
    pass


def parse_mpls_label(data: bytes, offset: int = 0) -> Dict[str, int]:
    """Parse MPLS label from 3 bytes of data.

    Args:
        data: Bytes containing MPLS label data
        offset: Starting offset in the data

    Returns:
        Dictionary with mpls_label, mpls_exp, and mpls_s fields

    Raises:
        ParseError: If insufficient data available
    """
    if len(data) < offset + 3:
        raise ParseError(f"Insufficient data for MPLS label: need 3 bytes, got {len(data) - offset}")

    label_bytes = data[offset:offset + 3]
    # MPLS label format: 20 bits label + 3 bits EXP + 1 bit S
    label_data = (label_bytes[0] << 16) | (label_bytes[1] << 8) | label_bytes[2]

    return {
        "mpls_label": (label_data >> 4) & 0xFFFFF,  # 20 bits (bits 23-4)
        "mpls_exp": (label_data >> 1) & 0x07,       # 3 bits (bits 3-1)
        "mpls_s": label_data & 0x01                 # 1 bit (bit 0)
    }


def parse_route_distinguisher(data: bytes) -> str:
    """Parse Route Distinguisher from 8 bytes of data.

    Args:
        data: 8 bytes of RD data

    Returns:
        String representation of the RD
    """
    if len(data) != 8:
        return data.hex()

    rd_type = struct.unpack(">H", data[0:2])[0]
    if rd_type == 0:  # Type 0: AS:Number
        asn = struct.unpack(">H", data[2:4])[0]
        num = struct.unpack(">I", data[4:8])[0]
        return f"{asn}:{num}"
    elif rd_type == 1:  # Type 1: IP:Number
        ip = ipaddress.IPv4Address(data[2:6])
        num = struct.unpack(">H", data[6:8])[0]
        return f"{ip}:{num}"
    else:
        return data.hex()


def parse_variable_length_ip(data: bytes, offset: int) -> Tuple[Optional[str], int]:
    """Parse variable length IP address from data.

    Args:
        data: Bytes containing IP length and address data
        offset: Starting offset in the data

    Returns:
        Tuple of (ip_address_string, new_offset)
        ip_address_string is None if length is 0

    Raises:
        ParseError: If insufficient data or invalid IP length
    """
    if len(data) <= offset:
        raise ParseError(f"Insufficient data for IP length at offset {offset}")

    ip_len_bits = data[offset]
    new_offset = offset + 1

    if ip_len_bits == 0:
        return None, new_offset

    ip_len_bytes = (ip_len_bits + 7) // 8  # Round up to nearest byte
    if len(data) < new_offset + ip_len_bytes:
        raise ParseError(f"Insufficient data for IP address: need {ip_len_bytes} bytes, got {len(data) - new_offset}")

    ip_bytes = data[new_offset:new_offset + ip_len_bytes]
    new_offset += ip_len_bytes

    try:
        if ip_len_bits == 32:  # IPv4
            return str(ipaddress.IPv4Address(ip_bytes)), new_offset
        elif ip_len_bits == 128:  # IPv6
            return str(ipaddress.IPv6Address(ip_bytes)), new_offset
        else:
            # Partial IP or other length - return hex representation
            return ip_bytes.hex(), new_offset
    except (ipaddress.AddressValueError, ValueError) as e:
        logger.warning(f"Invalid IP address data: {e}")
        return ip_bytes.hex(), new_offset


def parse_ip_prefix(data: bytes, offset: int) -> Tuple[Optional[str], int]:
    """Parse IP prefix with length from data.

    Args:
        data: Bytes containing prefix length and address data
        offset: Starting offset in the data

    Returns:
        Tuple of (prefix_string, new_offset)
        prefix_string is None if length is 0, otherwise in format "ip/length"

    Raises:
        ParseError: If insufficient data or invalid prefix
    """
    if len(data) <= offset:
        raise ParseError(f"Insufficient data for prefix length at offset {offset}")

    prefix_len = data[offset]
    new_offset = offset + 1

    if prefix_len == 0:
        return None, new_offset

    prefix_bytes = (prefix_len + 7) // 8  # Round up to nearest byte
    if len(data) < new_offset + prefix_bytes:
        raise ParseError(f"Insufficient data for IP prefix: need {prefix_bytes} bytes, got {len(data) - new_offset}")

    prefix_data = data[new_offset:new_offset + prefix_bytes]
    new_offset += prefix_bytes

    try:
        if prefix_len <= 32:  # IPv4
            # Pad to 4 bytes for IPv4
            padded_ip = prefix_data + bytes(4 - len(prefix_data))
            ip_addr = ipaddress.IPv4Address(padded_ip)
            return f"{ip_addr}/{prefix_len}", new_offset
        elif prefix_len <= 128:  # IPv6
            # Pad to 16 bytes for IPv6
            padded_ip = prefix_data + bytes(16 - len(prefix_data))
            ip_addr = ipaddress.IPv6Address(padded_ip)
            return f"{ip_addr}/{prefix_len}", new_offset
        else:
            # Invalid prefix length
            return f"{prefix_data.hex()}/{prefix_len}", new_offset
    except (ipaddress.AddressValueError, ValueError) as e:
        logger.warning(f"Invalid IP prefix data: {e}")
        return f"{prefix_data.hex()}/{prefix_len}", new_offset


def parse_mac_address(data: bytes, offset: int) -> Tuple[str, int]:
    """Parse MAC address from 6 bytes of data.

    Args:
        data: Bytes containing MAC address
        offset: Starting offset in the data

    Returns:
        Tuple of (mac_address_string, new_offset)

    Raises:
        ParseError: If insufficient data
    """
    if len(data) < offset + 6:
        raise ParseError(f"Insufficient data for MAC address: need 6 bytes, got {len(data) - offset}")

    mac_bytes = data[offset:offset + 6]
    mac_str = ":".join(f"{b:02x}" for b in mac_bytes)
    return mac_str, offset + 6


def safe_struct_unpack(format_str: str, data: bytes, offset: int = 0) -> Tuple[Any, int]:
    """Safely unpack struct data with bounds checking.

    Args:
        format_str: Struct format string (e.g., ">H", ">I")
        data: Bytes to unpack from
        offset: Starting offset in the data

    Returns:
        Tuple of (unpacked_value, new_offset)

    Raises:
        ParseError: If insufficient data or unpack error
    """
    size = struct.calcsize(format_str)
    if len(data) < offset + size:
        raise ParseError(f"Insufficient data for struct unpack: need {size} bytes, got {len(data) - offset}")

    try:
        value = struct.unpack(format_str, data[offset:offset + size])[0]
        return value, offset + size
    except struct.error as e:
        raise ParseError(f"Struct unpack error: {e}")


def validate_data_length(data: bytes, min_length: int, description: str = "data") -> None:
    """Validate that data has minimum required length.

    Args:
        data: Data to validate
        min_length: Minimum required length
        description: Description for error message

    Raises:
        ParseError: If data is too short
    """
    if len(data) < min_length:
        raise ParseError(f"Insufficient {description}: need {min_length} bytes, got {len(data)}")