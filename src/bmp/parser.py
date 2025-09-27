"""New modular BMP parser with delegated specialized parsers.

This is the new main parser that replaces the monolithic BMPParser.
It maintains the same public interface for backward compatibility while
delegating to specialized parser classes internally.
"""

import logging
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple, cast

from .bgp_parser import AFI, SAFI, BGPMessageParser
from .bmp_message_parser import BMPMessageParser, BMPMessageType
from .evpn_parser import EVPNParser
from .parsing_utils import ParseError, safe_struct_unpack, validate_data_length

logger = logging.getLogger(__name__)

# Export the enums for backward compatibility
__all__ = ["AFI", "SAFI", "BMPParser", "BMPPeerType", "BGPMessageType"]


class BMPPeerType(IntEnum):
    """BMP Peer Type values."""

    GLOBAL_INSTANCE = 0
    RD_INSTANCE = 1
    LOCAL_INSTANCE = 2


class BGPMessageType(IntEnum):
    """BGP message types."""

    OPEN = 1
    UPDATE = 2
    NOTIFICATION = 3
    KEEPALIVE = 4
    ROUTE_REFRESH = 5


class BMPParser:
    """Modular BMP parser with specialized components.

    This parser maintains the same interface as the original monolithic parser
    but delegates parsing to specialized classes for better maintainability.
    """

    def __init__(self):
        """Initialize the parser with all specialized components."""
        self.bgp_parser = BGPMessageParser()
        self.bmp_parser = BMPMessageParser()
        self.evpn_parser = EVPNParser()

        # Legacy buffer attribute for backward compatibility
        self.buffer = b""

        self.stats = {
            "messages_parsed": 0,
            "errors": 0,
            "route_monitoring": 0,
            "peer_up": 0,
            "peer_down": 0,
            "stats_reports": 0,
            "initiations": 0,
            "terminations": 0,
        }

    def parse_message(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Legacy method name for backward compatibility."""
        return self.parse_bmp_message(data)

    def parse_bmp_message(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse BMP message from raw bytes.

        This is the main entry point that maintains backward compatibility
        with the original parser interface.

        Args:
            data: Raw bytes containing BMP message

        Returns:
            Parsed message dictionary or None if parsing fails
        """
        try:
            # Validate minimum BMP header size
            validate_data_length(data, 6, "BMP header")

            # Parse BMP common header
            version, offset = safe_struct_unpack(">B", data, 0)
            if version != 3:
                logger.error(f"Unsupported BMP version: {version}")
                self.stats["errors"] += 1
                return None

            length, offset = safe_struct_unpack(">I", data, 1)
            msg_type, offset = safe_struct_unpack(">B", data, 5)

            # Validate message length
            if len(data) != length:
                logger.error(f"BMP message length mismatch: expected {length}, got {len(data)}")
                self.stats["errors"] += 1
                return None

            # Extract message payload (everything after 6-byte header)
            payload = data[6:]

            # Delegate to appropriate parser based on message type
            result = self._dispatch_message(msg_type, payload)

            if result:
                self.stats["messages_parsed"] += 1
                self._update_message_stats(msg_type)
            else:
                self.stats["errors"] += 1

            return result

        except ParseError as e:
            logger.error(f"BMP parsing error: {e}")
            self.stats["errors"] += 1
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing BMP message: {e}")
            self.stats["errors"] += 1
            return None

    def _dispatch_message(self, msg_type: int, payload: bytes) -> Optional[Dict[str, Any]]:
        """Dispatch message parsing to appropriate specialized parser."""
        try:
            if msg_type == BMPMessageType.ROUTE_MONITORING:
                return self._parse_route_monitoring(payload)
            elif msg_type == BMPMessageType.PEER_UP:
                return cast(Dict[str, Any], self.bmp_parser.parse_peer_up(payload))
            elif msg_type == BMPMessageType.PEER_DOWN:
                return cast(Dict[str, Any], self.bmp_parser.parse_peer_down(payload))
            elif msg_type == BMPMessageType.STATS_REPORT:
                return cast(Dict[str, Any], self.bmp_parser.parse_stats_report(payload))
            elif msg_type == BMPMessageType.INITIATION:
                return cast(Dict[str, Any], self.bmp_parser.parse_initiation(payload))
            elif msg_type == BMPMessageType.TERMINATION:
                return cast(Dict[str, Any], self.bmp_parser.parse_termination(payload))
            else:
                logger.warning(f"Unknown BMP message type: {msg_type}")
                return None

        except Exception as e:
            logger.error(f"Error dispatching message type {msg_type}: {e}")
            return None

    def _parse_route_monitoring(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse ROUTE_MONITORING message.

        This combines per-peer header parsing with BGP message parsing.
        """
        try:
            # Parse per-peer header
            peer_header, offset = self.bmp_parser.parse_per_peer_header(data)

            # Parse BGP message
            if offset < len(data):
                bgp_message = self.bgp_parser.parse_bgp_message(data[offset:])
                if bgp_message is None:
                    logger.error("Failed to parse BGP message in ROUTE_MONITORING")
                    return None
                return {"type": "route_monitoring", "peer": peer_header, "bgp_message": bgp_message}
            else:
                logger.error("No BGP message data in ROUTE_MONITORING")
                return None

        except Exception as e:
            logger.error(f"Error parsing ROUTE_MONITORING message: {e}")
            return None

    def _update_message_stats(self, msg_type: int) -> None:
        """Update internal statistics based on message type."""
        type_map = {
            BMPMessageType.ROUTE_MONITORING: "route_monitoring",
            BMPMessageType.PEER_UP: "peer_up",
            BMPMessageType.PEER_DOWN: "peer_down",
            BMPMessageType.STATS_REPORT: "stats_reports",
            BMPMessageType.INITIATION: "initiations",
            BMPMessageType.TERMINATION: "terminations",
        }

        stat_name = type_map.get(BMPMessageType(msg_type))
        if stat_name:
            self.stats[stat_name] += 1

    def get_stats(self) -> Dict[str, int]:
        """Get parser statistics.

        Maintains backward compatibility with original parser.
        """
        return cast(Dict[str, int], self.stats.copy())

    def reset_stats(self) -> None:
        """Reset parser statistics."""
        for key in self.stats:
            self.stats[key] = 0

    # Legacy methods for backward compatibility
    def _parse_per_peer_header(self, data: bytes) -> Tuple[Dict[str, Any], int]:
        """Legacy method for backward compatibility."""
        try:
            return cast(Tuple[Dict[str, Any], int], self.bmp_parser.parse_per_peer_header(data))
        except ParseError as e:
            if "per-peer header" in str(e):
                raise ValueError("Insufficient data for per-peer header") from e
            raise

    def _parse_bgp_message(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Legacy method for backward compatibility."""
        return cast(Optional[Dict[str, Any]], self.bgp_parser.parse_bgp_message(data))

    def _parse_evpn_route(self, route_type: int, data: bytes) -> Optional[Dict[str, Any]]:
        """Legacy method for backward compatibility."""
        return cast(Optional[Dict[str, Any]], self.evpn_parser.parse_evpn_route(route_type, data))

    def _parse_route_distinguisher(self, data: bytes) -> str:
        """Legacy method for backward compatibility."""
        from .parsing_utils import parse_route_distinguisher

        return parse_route_distinguisher(data)

    # Additional legacy methods that might be called by external code
    def _parse_peer_up(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        return cast(Dict[str, Any], self.bmp_parser.parse_peer_up(data))

    def _parse_peer_down(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        return cast(Dict[str, Any], self.bmp_parser.parse_peer_down(data))

    def _parse_stats_report(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        return cast(Dict[str, Any], self.bmp_parser.parse_stats_report(data))

    def _parse_initiation(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        return cast(Dict[str, Any], self.bmp_parser.parse_initiation(data))

    def _parse_termination(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        return cast(Dict[str, Any], self.bmp_parser.parse_termination(data))

    # Additional legacy methods that tests expect
    def _parse_bgp_update(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Legacy method for backward compatibility."""
        return cast(Optional[Dict[str, Any]], self.bgp_parser._parse_bgp_update(data))

    def _parse_bgp_open(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        try:
            return cast(Dict[str, Any], self.bgp_parser._parse_bgp_open(data))
        except ParseError as e:
            return {"type": "OPEN", "error": str(e)}

    def _parse_as_path(self, data: bytes) -> List[Dict[str, Any]]:
        """Legacy method for backward compatibility."""
        # Convert the modern format to the legacy format expected by tests
        legacy_format = []
        offset = 0

        while offset < len(data):
            if offset + 2 > len(data):
                break

            path_type = data[offset]
            path_length = data[offset + 1]
            offset += 2

            if offset + (path_length * 4) > len(data):  # 4-byte AS numbers
                break

            # Parse AS numbers (4-byte)
            as_numbers = []
            for _ in range(path_length):
                as_num, offset = safe_struct_unpack(">I", data, offset)
                as_numbers.append(as_num)

            # Determine type name
            type_name = (
                "AS_SEQUENCE"
                if path_type == 2
                else "AS_SET"
                if path_type == 1
                else f"AS_TYPE_{path_type}"
            )

            legacy_format.append({"type": type_name, "as_numbers": as_numbers})

        return legacy_format

    def _parse_communities(self, data: bytes) -> List[str]:
        """Legacy method for backward compatibility."""
        return cast(List[str], self.bgp_parser._parse_communities(data))

    def _parse_large_communities(self, data: bytes) -> List[str]:
        """Legacy method for backward compatibility."""
        return cast(List[str], self.bgp_parser._parse_large_communities(data))

    def _parse_nlri(self, data: bytes, afi: int = 1) -> List[str]:
        """Legacy method for backward compatibility with AFI parameter."""
        if afi == 1:  # IPv4
            return cast(List[str], self.bgp_parser._parse_nlri_prefixes(data))
        elif afi == 2:  # IPv6
            return cast(List[str], self.bgp_parser._parse_ipv6_nlri(data))
        else:
            return [data.hex()]

    def _parse_mp_reach_nlri(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        result = self.bgp_parser._parse_mp_reach_nlri(data)
        return cast(Dict[str, Any], result if result is not None else {})

    def _parse_mp_unreach_nlri(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        result = self.bgp_parser._parse_mp_unreach_nlri(data)
        return cast(Dict[str, Any], result if result is not None else {})

    def _parse_tlvs(self, data: bytes) -> List[Dict[str, Any]]:
        """Legacy method for backward compatibility."""
        return cast(List[Dict[str, Any]], self.bmp_parser._parse_tlvs(data))

    def _parse_capabilities(self, data: bytes) -> List[Dict[str, Any]]:
        """Legacy method for backward compatibility."""
        # Handle both formats - direct capability data and option-wrapped data
        if len(data) >= 2 and data[0] == 2:  # Option type 2 (Capability)
            return cast(List[Dict[str, Any]], self.bgp_parser._parse_capabilities(data))
        else:
            # Direct capability data format for tests
            capabilities = []
            offset = 0

            while offset < len(data):
                if offset + 2 > len(data):
                    break

                cap_code = data[offset]
                cap_len = data[offset + 1]
                offset += 2

                if offset + cap_len > len(data):
                    break

                cap_value = data[offset : offset + cap_len]
                capabilities.append({"code": cap_code, "length": cap_len, "value": cap_value.hex()})
                offset += cap_len

            return capabilities

    def _parse_path_attributes(self, data: bytes) -> List[Dict[str, Any]]:
        """Legacy method for backward compatibility."""
        return cast(List[Dict[str, Any]], self.bgp_parser._parse_path_attributes(data))
