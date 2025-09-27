"""Input validation utilities for BMP collector."""
import ipaddress
from typing import Any, Optional


def validate_as_number(as_num: Any) -> Optional[int]:
    """Validate and return AS number if valid."""
    try:
        # Handle special float values
        if isinstance(as_num, float):
            if not (as_num == as_num):  # Check for NaN
                return None
            if as_num == float("inf") or as_num == float("-inf"):
                return None

        as_val = int(as_num)
        if 0 <= as_val <= 4294967295:  # Valid 32-bit AS range
            return as_val
    except (ValueError, TypeError, OverflowError):
        pass
    return None


def validate_ip_address(ip: Any) -> Optional[str]:
    """Validate and return IP address if valid."""
    try:
        # Only accept string input for IP addresses
        if not isinstance(ip, str):
            return None
        # Try IPv4 first
        addr = ipaddress.ip_address(ip)
        return str(addr)
    except (ValueError, TypeError, ipaddress.AddressValueError):
        return None


def validate_prefix(prefix: Any) -> Optional[str]:
    """Validate and return network prefix if valid."""
    try:
        # Only accept string input and must contain '/'
        if not isinstance(prefix, str) or "/" not in prefix:
            return None
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
        # Handle special float values
        if isinstance(port, float):
            if not (port == port):  # Check for NaN
                return None
            if port == float("inf") or port == float("-inf"):
                return None

        port_val = int(port)
        if 1 <= port_val <= 65535:
            return port_val
    except (ValueError, TypeError, OverflowError):
        pass
    return None


def sanitize_log_data(data: Any, max_len: int = 100) -> str:
    """Sanitize data for safe logging."""
    import re

    if isinstance(data, bytes):
        # Convert bytes to hex representation
        hex_str = data.hex()
        if len(hex_str) > max_len:
            return hex_str[:max_len] + "..."
        return hex_str

    str_data = str(data)

    # Remove XSS patterns
    xss_patterns = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"alert\(",
        r"<[a-zA-Z][^>]*>",  # Remove HTML tags (must start with letter)
        r"</[a-zA-Z][^>]*>",  # Remove HTML closing tags
        r"on\w+\s*=",  # Remove event handlers like onclick=
    ]

    sanitized = str_data
    for pattern in xss_patterns:
        sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE | re.DOTALL)

    # Remove potential control characters (but keep tabs for readability)
    sanitized = "".join(char if char.isprintable() or char in "\t" else "?" for char in sanitized)

    # Remove null bytes and other binary data
    sanitized = sanitized.replace("\x00", "?")
    sanitized = sanitized.replace("\x01", "?")
    sanitized = sanitized.replace("\x02", "?")
    sanitized = sanitized.replace("\x03", "?")

    if len(sanitized) > max_len:
        return sanitized[:max_len] + "..."
    return sanitized
