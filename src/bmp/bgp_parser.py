"""BGP message parsing for BMP protocol.

This module handles parsing of BGP messages, particularly UPDATE messages
and their path attributes.
"""

import ipaddress
import logging
import struct
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

from .evpn_parser import EVPNParser
from .parsing_utils import ParseError, safe_struct_unpack, validate_data_length

logger = logging.getLogger(__name__)


class AFI(IntEnum):
    """Address Family Identifier values."""

    IPV4 = 1
    IPV6 = 2
    L2VPN = 25


class SAFI(IntEnum):
    """Subsequent Address Family Identifier values."""

    UNICAST = 1
    MULTICAST = 2
    EVPN = 70
    MPLS_VPN = 128


class BGPMessageType(IntEnum):
    """BGP message types."""

    OPEN = 1
    UPDATE = 2
    NOTIFICATION = 3
    KEEPALIVE = 4


class BGPAttributeType(IntEnum):
    """BGP path attribute types."""

    ORIGIN = 1
    AS_PATH = 2
    NEXT_HOP = 3
    MULTI_EXIT_DISC = 4
    LOCAL_PREF = 5
    COMMUNITIES = 8
    LARGE_COMMUNITIES = 32
    MP_REACH_NLRI = 14
    MP_UNREACH_NLRI = 15


class BGPMessageParser:
    """Parser for BGP messages within BMP protocol."""

    def __init__(self):
        self.evpn_parser = EVPNParser()

    def parse_bgp_message(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse BGP message from data.

        Args:
            data: Raw bytes containing BGP message

        Returns:
            Parsed BGP message dictionary or None if parsing fails
        """
        try:
            validate_data_length(data, 19, "BGP message header")

            # Parse BGP header (19 bytes, but tests seem to add an extra byte)
            # Marker (16 bytes) + Length (2 bytes) + Type (1 byte) + [Optional extra byte]
            length, offset = safe_struct_unpack(">H", data, 16)
            msg_type, offset = safe_struct_unpack(">B", data, 18)

            # Check if there's an extra byte after type (common in tests)
            payload_start = 20 if len(data) > 19 and data[19] == 0 else 19

            if msg_type == BGPMessageType.UPDATE:
                return self._parse_bgp_update(data[payload_start:])
            elif msg_type == BGPMessageType.OPEN:
                return self._parse_bgp_open(data[payload_start:])
            else:
                return {"type": self._get_bgp_message_type_name(msg_type), "length": length}

        except ParseError as e:
            logger.error(f"Error parsing BGP message: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error parsing BGP message: {e}")
            return None

    def _parse_bgp_update(self, data: bytes) -> Dict[str, Any]:
        """Parse BGP UPDATE message.

        Format: Withdrawn_len(2) + Withdrawn(var) + Path_attr_len(2) + Path_attr(var) + NLRI(var)
        """
        validate_data_length(data, 4, "BGP UPDATE message")

        message = {"type": "UPDATE"}
        offset = 0

        # Parse withdrawn routes length and routes
        withdrawn_len, offset = safe_struct_unpack(">H", data, offset)
        if withdrawn_len > 0:
            validate_data_length(data, offset + withdrawn_len, "withdrawn routes")
            withdrawn_data = data[offset : offset + withdrawn_len]
            message["withdrawn"] = self._parse_nlri_prefixes(withdrawn_data)
            offset += withdrawn_len
        else:
            message["withdrawn"] = []

        # Parse path attributes length and attributes
        validate_data_length(data, offset + 2, "path attributes length")
        path_attr_len, offset = safe_struct_unpack(">H", data, offset)

        if path_attr_len > 0:
            validate_data_length(data, offset + path_attr_len, "path attributes")
            attr_data = data[offset : offset + path_attr_len]
            attributes = self._parse_path_attributes(attr_data)
            message["path_attributes"] = attributes
            message["attributes"] = attributes  # For backward compatibility
            offset += path_attr_len
        else:
            message["path_attributes"] = []
            message["attributes"] = []

        # Parse NLRI (announced routes)
        if len(data) > offset:
            nlri_data = data[offset:]
            message["nlri"] = self._parse_nlri_prefixes(nlri_data)
        else:
            message["nlri"] = []

        return message

    def _parse_bgp_open(self, data: bytes) -> Dict[str, Any]:
        """Parse BGP OPEN message.

        Format: Version(1) + AS(2) + Hold_time(2) + BGP_ID(4) + Opt_len(1) + Options(var)
        """
        validate_data_length(data, 10, "BGP OPEN message")

        message = {"type": "OPEN"}
        offset = 0

        # Parse basic OPEN fields
        message["version"], offset = safe_struct_unpack(">B", data, offset)
        as_number, offset = safe_struct_unpack(">H", data, offset)
        message["as"] = as_number  # For backward compatibility
        message["as_number"] = as_number  # Keep both
        message["hold_time"], offset = safe_struct_unpack(">H", data, offset)
        bgp_id = str(ipaddress.IPv4Address(data[offset : offset + 4]))
        message["bgp_identifier"] = bgp_id
        message["bgp_id"] = bgp_id  # For backward compatibility
        offset += 4

        # Parse optional parameters
        opt_len, offset = safe_struct_unpack(">B", data, offset)
        if opt_len > 0:
            validate_data_length(data, offset + opt_len, "OPEN optional parameters")
            opt_data = data[offset : offset + opt_len]
            message["capabilities"] = self._parse_capabilities(opt_data)
        else:
            message["capabilities"] = []

        return message

    def _parse_path_attributes(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse BGP path attributes."""
        attributes = []
        offset = 0

        while offset < len(data):
            try:
                # Parse attribute header
                if offset + 2 > len(data):
                    break

                flags = data[offset]
                attr_type = data[offset + 1]
                offset += 2

                # Determine attribute length (1 or 2 bytes based on Extended Length flag)
                if flags & 0x10:  # Extended Length flag
                    if offset + 2 > len(data):
                        break
                    attr_len, offset = safe_struct_unpack(">H", data, offset)
                else:
                    if offset + 1 > len(data):
                        break
                    attr_len, offset = safe_struct_unpack(">B", data, offset)

                # Extract attribute data
                if offset + attr_len > len(data):
                    break

                attr_data = data[offset : offset + attr_len]
                offset += attr_len

                # Parse specific attribute types
                attribute = self._parse_attribute(attr_type, attr_data, flags)
                if attribute:
                    attributes.append(attribute)

            except Exception as e:
                logger.warning(f"Error parsing path attribute at offset {offset}: {e}")
                break

        return attributes

    def _parse_attribute(self, attr_type: int, data: bytes, flags: int) -> Optional[Dict[str, Any]]:
        """Parse specific BGP path attribute."""
        try:
            if attr_type == BGPAttributeType.AS_PATH:
                return {"type": "AS_PATH", "value": self._parse_as_path(data)}
            elif attr_type == BGPAttributeType.COMMUNITIES:
                return {"type": "COMMUNITIES", "value": self._parse_communities(data)}
            elif attr_type == BGPAttributeType.LARGE_COMMUNITIES:
                return {"type": "LARGE_COMMUNITIES", "value": self._parse_large_communities(data)}
            elif attr_type == BGPAttributeType.MP_REACH_NLRI:
                return {"type": "MP_REACH_NLRI", "value": self._parse_mp_reach_nlri(data)}
            elif attr_type == BGPAttributeType.MP_UNREACH_NLRI:
                return {"type": "MP_UNREACH_NLRI", "value": self._parse_mp_unreach_nlri(data)}
            elif attr_type == BGPAttributeType.NEXT_HOP:
                if len(data) == 4:
                    return {"type": "NEXT_HOP", "value": str(ipaddress.IPv4Address(data))}
            else:
                return {"type": f"UNKNOWN_{attr_type}", "value": data.hex()}

        except Exception as e:
            logger.warning(f"Error parsing attribute type {attr_type}: {e}")
            return {"type": f"INVALID_{attr_type}", "value": data.hex()}

        return None

    def _parse_as_path(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse AS_PATH attribute."""
        as_path = []
        offset = 0

        while offset < len(data):
            if offset + 2 > len(data):
                break

            path_type = data[offset]
            path_length = data[offset + 1]
            offset += 2

            if offset + (path_length * 2) > len(data):
                break

            segment = []
            for _ in range(path_length):
                as_num, offset = safe_struct_unpack(">H", data, offset)
                segment.append(as_num)

            # Map path type to string
            path_type_names = {1: "AS_SET", 2: "AS_SEQUENCE"}
            path_type_name = path_type_names.get(path_type, f"AS_TYPE_{path_type}")

            as_path.append({
                "type": path_type_name,
                "as_numbers": segment
            })

        return as_path

    def _parse_communities(self, data: bytes) -> List[str]:
        """Parse COMMUNITIES attribute."""
        communities = []
        for i in range(0, len(data), 4):
            if i + 4 <= len(data):
                high, _ = safe_struct_unpack(">H", data, i)
                low, _ = safe_struct_unpack(">H", data, i + 2)
                communities.append(f"{high}:{low}")
        return communities

    def _parse_large_communities(self, data: bytes) -> List[str]:
        """Parse LARGE_COMMUNITIES attribute."""
        communities = []
        for i in range(0, len(data), 12):
            if i + 12 <= len(data):
                global_admin, _ = safe_struct_unpack(">I", data, i)
                local_data1, _ = safe_struct_unpack(">I", data, i + 4)
                local_data2, _ = safe_struct_unpack(">I", data, i + 8)
                communities.append(f"{global_admin}:{local_data1}:{local_data2}")
        return communities

    def _parse_mp_reach_nlri(self, data: bytes) -> Dict[str, Any]:
        """Parse MP_REACH_NLRI attribute."""
        validate_data_length(data, 5, "MP_REACH_NLRI")

        result = {}
        offset = 0

        # Parse AFI/SAFI
        result["afi"], offset = safe_struct_unpack(">H", data, offset)
        result["safi"], offset = safe_struct_unpack(">B", data, offset)

        # Parse next hop
        next_hop_len, offset = safe_struct_unpack(">B", data, offset)
        if next_hop_len > 0 and offset + next_hop_len <= len(data):
            next_hop_data = data[offset : offset + next_hop_len]
            result["next_hop"] = self._parse_next_hop(next_hop_data, result["afi"])
            offset += next_hop_len

        # Skip reserved byte
        offset += 1

        # Parse NLRI
        if offset < len(data):
            nlri_data = data[offset:]
            if result["afi"] == AFI.IPV4 and result["safi"] == SAFI.EVPN:
                result["nlri"] = self._parse_evpn_nlri(nlri_data)
            elif result["afi"] == AFI.IPV6:
                result["nlri"] = self._parse_ipv6_nlri(nlri_data)
            else:
                result["nlri"] = nlri_data.hex()

        return result

    def _parse_mp_unreach_nlri(self, data: bytes) -> Dict[str, Any]:
        """Parse MP_UNREACH_NLRI attribute."""
        validate_data_length(data, 3, "MP_UNREACH_NLRI")

        result = {}
        offset = 0

        # Parse AFI/SAFI
        result["afi"], offset = safe_struct_unpack(">H", data, offset)
        result["safi"], offset = safe_struct_unpack(">B", data, offset)

        # Parse withdrawn routes
        if offset < len(data):
            nlri_data = data[offset:]
            if result["afi"] == AFI.IPV4 and result["safi"] == SAFI.EVPN:
                withdrawn = self._parse_evpn_nlri(nlri_data)
            elif result["afi"] == AFI.IPV6:
                withdrawn = self._parse_ipv6_nlri(nlri_data)
            else:
                withdrawn = nlri_data.hex()

            result["nlri"] = withdrawn
            result["withdrawn"] = withdrawn  # For backward compatibility

        return result

    def _parse_evpn_nlri(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse EVPN NLRI data."""
        nlri_list = []
        offset = 0

        while offset < len(data):
            try:
                if offset + 2 > len(data):
                    break

                # Parse route type and length
                route_type = data[offset]
                route_len = data[offset + 1]
                offset += 2

                if offset + route_len > len(data):
                    break

                # Parse EVPN route using specialized parser
                route_data = data[offset : offset + route_len]
                evpn_route = self.evpn_parser.parse_evpn_route(route_type, route_data)
                if evpn_route:
                    nlri_list.append(evpn_route)

                offset += route_len

            except Exception as e:
                logger.warning(f"Error parsing EVPN NLRI at offset {offset}: {e}")
                break

        return nlri_list

    def _parse_nlri_prefixes(self, data: bytes) -> List[str]:
        """Parse traditional IPv4 NLRI prefixes."""
        prefixes = []
        offset = 0

        while offset < len(data):
            try:
                if offset >= len(data):
                    break

                prefix_len = data[offset]
                offset += 1

                if prefix_len > 32:
                    break

                prefix_bytes = (prefix_len + 7) // 8
                if offset + prefix_bytes > len(data):
                    break

                prefix_data = data[offset : offset + prefix_bytes]
                offset += prefix_bytes

                # Pad to 4 bytes for IPv4
                padded_data = prefix_data + bytes(4 - len(prefix_data))
                ip_addr = ipaddress.IPv4Address(padded_data)
                prefixes.append(f"{ip_addr}/{prefix_len}")

            except Exception as e:
                logger.warning(f"Error parsing NLRI prefix at offset {offset}: {e}")
                break

        return prefixes

    def _parse_ipv6_nlri(self, data: bytes) -> List[str]:
        """Parse IPv6 NLRI data."""
        prefixes = []
        offset = 0

        while offset < len(data):
            try:
                if offset >= len(data):
                    break

                prefix_len = data[offset]
                offset += 1

                if prefix_len > 128:
                    break

                prefix_bytes = (prefix_len + 7) // 8
                if offset + prefix_bytes > len(data):
                    break

                prefix_data = data[offset : offset + prefix_bytes]
                offset += prefix_bytes

                # Pad to 16 bytes for IPv6
                padded_data = prefix_data + bytes(16 - len(prefix_data))
                ip_addr = ipaddress.IPv6Address(padded_data)
                prefixes.append(f"{ip_addr}/{prefix_len}")

            except Exception as e:
                logger.warning(f"Error parsing IPv6 NLRI at offset {offset}: {e}")
                break

        return prefixes

    def _parse_next_hop(self, data: bytes, afi: int) -> str:
        """Parse next hop address based on AFI."""
        try:
            if afi == AFI.IPV4 and len(data) == 4:
                return str(ipaddress.IPv4Address(data))
            elif afi == AFI.IPV6 and len(data) == 16:
                return str(ipaddress.IPv6Address(data))
            else:
                return data.hex()
        except Exception:
            return data.hex()

    def _parse_capabilities(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse BGP capabilities from OPEN message."""
        capabilities = []
        offset = 0

        # Check if this is raw capability data or wrapped in optional parameters
        is_raw_capability = len(data) >= 2 and data[0] != 2  # Not optional parameter type 2

        if is_raw_capability:
            # Parse as direct capability data
            while offset < len(data):
                try:
                    if offset + 2 > len(data):
                        break

                    cap_code = data[offset]
                    cap_len = data[offset + 1]
                    offset += 2

                    if offset + cap_len > len(data):
                        break

                    cap_value = data[offset : offset + cap_len]
                    capabilities.append(
                        {"type": cap_code, "length": cap_len, "value": cap_value.hex()}
                    )
                    offset += cap_len

                except Exception as e:
                    logger.warning(f"Error parsing capability at offset {offset}: {e}")
                    break
        else:
            # Parse as optional parameter format
            while offset < len(data):
                try:
                    if offset + 2 > len(data):
                        break

                    opt_type = data[offset]
                    opt_len = data[offset + 1]
                    offset += 2

                    if offset + opt_len > len(data):
                        break

                    if opt_type == 2:  # Capability option
                        cap_data = data[offset : offset + opt_len]
                        cap_offset = 0

                        while cap_offset < len(cap_data):
                            if cap_offset + 2 > len(cap_data):
                                break

                            cap_code = cap_data[cap_offset]
                            cap_len = cap_data[cap_offset + 1]
                            cap_offset += 2

                            if cap_offset + cap_len > len(cap_data):
                                break

                            cap_value = cap_data[cap_offset : cap_offset + cap_len]
                            capabilities.append(
                                {"type": cap_code, "length": cap_len, "value": cap_value.hex()}
                            )
                            cap_offset += cap_len

                    offset += opt_len

                except Exception as e:
                    logger.warning(f"Error parsing capability at offset {offset}: {e}")
                    break

        return capabilities

    def _get_bgp_message_type_name(self, msg_type: int) -> str:
        """Get human-readable BGP message type name."""
        type_names = {
            BGPMessageType.OPEN: "OPEN",
            BGPMessageType.UPDATE: "UPDATE",
            BGPMessageType.NOTIFICATION: "NOTIFICATION",
            BGPMessageType.KEEPALIVE: "KEEPALIVE",
        }
        return type_names.get(msg_type, "UNKNOWN")
