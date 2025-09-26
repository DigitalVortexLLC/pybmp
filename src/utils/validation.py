"""Input validation utilities for BMP collector."""
import ipaddress
import struct
from typing import Any, Optional


def validate_as_number(as_num: Any) -> Optional[int]:
    """Validate and return AS number if valid."""
    try:
        as_val = int(as_num)
        if 0 <= as_val <= 4294967295:  # Valid 32-bit AS range
            return as_val
    except (ValueError, TypeError):
        pass
    return None


def validate_ip_address(ip: Any) -> Optional[str]:
    """Validate and return IP address if valid."""
    try:
        # Try IPv4 first
        addr = ipaddress.ip_address(ip)
        return str(addr)
    except (ValueError, TypeError, ipaddress.AddressValueError):
        return None


def validate_prefix(prefix: Any) -> Optional[str]:
    """Validate and return network prefix if valid."""
    try:
        network = ipaddress.ip_network(prefix, strict=False)
        return str(network)
    except (ValueError, TypeError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return None


def validate_message_length(length: int, max_size: int = 1048576) -> bool:
    """Validate BMP message length."""
    # Minimum BMP message is 6 bytes (header)
    # Maximum reasonable size is 1MB by default
    return 6 <= length <= max_size


def validate_port(port: Any) -> Optional[int]:
    """Validate TCP/UDP port number."""
    try:
        port_val = int(port)
        if 1 <= port_val <= 65535:
            return port_val
    except (ValueError, TypeError):
        pass
    return None


def sanitize_log_data(data: Any, max_len: int = 100) -> str:
    """Sanitize data for safe logging."""
    if isinstance(data, bytes):
        # Convert bytes to hex representation
        hex_str = data.hex()
        if len(hex_str) > max_len:
            return hex_str[:max_len] + "..."
        return hex_str

    str_data = str(data)
    # Remove potential control characters
    sanitized = ''.join(char if char.isprintable() else '?' for char in str_data)

    if len(sanitized) > max_len:
        return sanitized[:max_len] + "..."
    return sanitized