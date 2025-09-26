"""New modular BMP parser with delegated specialized parsers.

This is the new main parser that replaces the monolithic BMPParser.
It maintains the same public interface for backward compatibility while
delegating to specialized parser classes internally.
"""

import struct
import logging
from typing import Dict, Any, Optional, List
from enum import IntEnum

from .parsing_utils import safe_struct_unpack, validate_data_length, ParseError
from .bgp_parser import BGPMessageParser, AFI, SAFI
from .bmp_message_parser import BMPMessageParser, BMPMessageType
from .evpn_parser import EVPNParser

logger = logging.getLogger(__name__)


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
        self.stats = {
            "messages_parsed": 0,
            "errors": 0,
            "route_monitoring": 0,
            "peer_up": 0,
            "peer_down": 0,
            "stats_reports": 0,
            "initiations": 0,
            "terminations": 0
        }

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
                return self.bmp_parser.parse_peer_up(payload)
            elif msg_type == BMPMessageType.PEER_DOWN:
                return self.bmp_parser.parse_peer_down(payload)
            elif msg_type == BMPMessageType.STATS_REPORT:
                return self.bmp_parser.parse_stats_report(payload)
            elif msg_type == BMPMessageType.INITIATION:
                return self.bmp_parser.parse_initiation(payload)
            elif msg_type == BMPMessageType.TERMINATION:
                return self.bmp_parser.parse_termination(payload)
            else:
                logger.warning(f"Unknown BMP message type: {msg_type}")
                return {"type": f"unknown_{msg_type}", "data": payload.hex()}

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

                return {
                    "type": "route_monitoring",
                    "peer": peer_header,
                    "bgp_message": bgp_message
                }
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
            BMPMessageType.TERMINATION: "terminations"
        }

        stat_name = type_map.get(msg_type)
        if stat_name:
            self.stats[stat_name] += 1

    def get_stats(self) -> Dict[str, int]:
        """Get parser statistics.

        Maintains backward compatibility with original parser.
        """
        return self.stats.copy()

    def reset_stats(self) -> None:
        """Reset parser statistics."""
        for key in self.stats:
            self.stats[key] = 0

    # Legacy methods for backward compatibility
    def _parse_per_peer_header(self, data: bytes) -> Tuple[Dict[str, Any], int]:
        """Legacy method for backward compatibility."""
        return self.bmp_parser.parse_per_peer_header(data)

    def _parse_bgp_message(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Legacy method for backward compatibility."""
        return self.bgp_parser.parse_bgp_message(data)

    def _parse_evpn_route(self, route_type: int, data: bytes) -> Optional[Dict[str, Any]]:
        """Legacy method for backward compatibility."""
        return self.evpn_parser.parse_evpn_route(route_type, data)

    def _parse_route_distinguisher(self, data: bytes) -> str:
        """Legacy method for backward compatibility."""
        from .parsing_utils import parse_route_distinguisher
        return parse_route_distinguisher(data)

    # Additional legacy methods that might be called by external code
    def _parse_peer_up(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        return self.bmp_parser.parse_peer_up(data)

    def _parse_peer_down(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        return self.bmp_parser.parse_peer_down(data)

    def _parse_stats_report(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        return self.bmp_parser.parse_stats_report(data)

    def _parse_initiation(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        return self.bmp_parser.parse_initiation(data)

    def _parse_termination(self, data: bytes) -> Dict[str, Any]:
        """Legacy method for backward compatibility."""
        return self.bmp_parser.parse_termination(data)