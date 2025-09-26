"""EVPN route parsing for BMP protocol.

This module handles parsing of all EVPN route types (1-5) with dedicated
methods for each type, eliminating the complexity of the original monolithic parser.
"""

import logging
from typing import Dict, Any, Optional

from .parsing_utils import (
    parse_mpls_label, parse_route_distinguisher, parse_variable_length_ip,
    parse_ip_prefix, parse_mac_address, safe_struct_unpack, validate_data_length,
    ParseError
)

logger = logging.getLogger(__name__)


class EVPNParser:
    """Parser for EVPN route types."""

    def parse_evpn_route(self, route_type: int, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse EVPN route based on route type.

        Args:
            route_type: EVPN route type (1-5)
            data: Raw bytes containing the EVPN route data

        Returns:
            Parsed route dictionary or None if parsing fails
        """
        try:
            # Dispatch to specific parser based on route type
            parsers = {
                1: self._parse_ethernet_auto_discovery,
                2: self._parse_mac_ip_advertisement,
                3: self._parse_inclusive_multicast,
                4: self._parse_ethernet_segment,
                5: self._parse_ip_prefix
            }

            parser_func = parsers.get(route_type)
            if not parser_func:
                logger.warning(f"Unknown EVPN route type: {route_type}")
                return {"type": route_type, "name": "Unknown"}

            return parser_func(data)

        except ParseError as e:
            logger.error(f"Error parsing EVPN route type {route_type}: {e}")
            # Return minimal result for insufficient data rather than None
            type_names = {
                1: "Ethernet Auto-Discovery",
                2: "MAC/IP Advertisement",
                3: "Inclusive Multicast",
                4: "Ethernet Segment",
                5: "IP Prefix"
            }
            return {
                "type": route_type,
                "name": type_names.get(route_type, "Unknown"),
                "error": str(e),
                "data": data.hex()
            }
        except Exception as e:
            logger.error(f"Unexpected error parsing EVPN route type {route_type}: {e}")
            return None

    def _parse_ethernet_auto_discovery(self, data: bytes) -> Dict[str, Any]:
        """Parse EVPN Route Type 1: Ethernet Auto-Discovery.

        Format: RD(8) + ESI(10) + EthTag(4) + Label(3) = 25 bytes minimum
        """
        validate_data_length(data, 25, "Ethernet Auto-Discovery route")

        route = {"type": 1, "name": "Ethernet Auto-Discovery"}

        # Parse Route Distinguisher (8 bytes)
        route["rd"] = parse_route_distinguisher(data[0:8])

        # Parse ESI (10 bytes)
        route["esi"] = data[8:18].hex()

        # Parse Ethernet Tag (4 bytes)
        route["eth_tag"], _ = safe_struct_unpack(">I", data, 18)

        # Parse MPLS Label (3 bytes)
        if len(data) >= 25:
            mpls_info = parse_mpls_label(data, 22)
            route.update(mpls_info)

        return route

    def _parse_mac_ip_advertisement(self, data: bytes) -> Dict[str, Any]:
        """Parse EVPN Route Type 2: MAC/IP Advertisement.

        Format: RD(8) + ESI(10) + EthTag(4) + MAC_len(1) + MAC(6) + IP_len(1) + IP(var) + Label1(3) + Label2(3)
        """
        validate_data_length(data, 25, "MAC/IP Advertisement route")

        route = {"type": 2, "name": "MAC/IP Advertisement"}

        # Parse RD (8 bytes)
        route["rd"] = parse_route_distinguisher(data[0:8])

        # Parse ESI (10 bytes)
        route["esi"] = data[8:18].hex()

        # Parse Ethernet Tag (4 bytes)
        route["eth_tag"], _ = safe_struct_unpack(">I", data, 18)

        # Parse MAC length and address
        offset = 22
        mac_len = data[offset]
        offset += 1

        if mac_len == 48 and len(data) >= offset + 6:
            route["mac"], offset = parse_mac_address(data, offset)

            # Parse IP address (variable length)
            if len(data) > offset:
                ip_len_bits = data[offset]
                route["ip_length"] = ip_len_bits
                ip_address, offset = parse_variable_length_ip(data, offset)
                if ip_address:
                    route["ip_address"] = ip_address

                # Parse MPLS Label1 (3 bytes)
                if len(data) >= offset + 3:
                    mpls1_info = parse_mpls_label(data, offset)
                    # Add suffix to distinguish from potential second label
                    for key, value in mpls1_info.items():
                        route[f"{key}1"] = value
                    offset += 3

                    # Parse MPLS Label2 if present (3 bytes)
                    if len(data) >= offset + 3:
                        mpls2_info = parse_mpls_label(data, offset)
                        for key, value in mpls2_info.items():
                            route[f"{key}2"] = value

        return route

    def _parse_inclusive_multicast(self, data: bytes) -> Dict[str, Any]:
        """Parse EVPN Route Type 3: Inclusive Multicast Ethernet Tag.

        Format: RD(8) + EthTag(4) + IP_len(1) + IP(var) = 13+ bytes minimum
        """
        validate_data_length(data, 12, "Inclusive Multicast route")

        route = {"type": 3, "name": "Inclusive Multicast"}

        # Parse Route Distinguisher (8 bytes)
        route["rd"] = parse_route_distinguisher(data[0:8])

        # Parse Ethernet Tag (4 bytes)
        route["eth_tag"], _ = safe_struct_unpack(">I", data, 8)

        # Parse originating IP address (variable length)
        if len(data) > 12:
            ip_len_bits = data[12]
            route["ip_length"] = ip_len_bits
            originating_ip, _ = parse_variable_length_ip(data, 12)
            if originating_ip:
                route["originating_ip"] = originating_ip

        return route

    def _parse_ethernet_segment(self, data: bytes) -> Dict[str, Any]:
        """Parse EVPN Route Type 4: Ethernet Segment.

        Format: RD(8) + ESI(10) + IP_len(1) + IP(var) = 19+ bytes minimum
        """
        validate_data_length(data, 18, "Ethernet Segment route")

        route = {"type": 4, "name": "Ethernet Segment"}

        # Parse Route Distinguisher (8 bytes)
        route["rd"] = parse_route_distinguisher(data[0:8])

        # Parse ESI (10 bytes)
        route["esi"] = data[8:18].hex()

        # Parse originating IP address (variable length)
        if len(data) > 18:
            ip_len_bits = data[18]
            route["ip_length"] = ip_len_bits
            originating_ip, _ = parse_variable_length_ip(data, 18)
            if originating_ip:
                route["originating_ip"] = originating_ip

        return route

    def _parse_ip_prefix(self, data: bytes) -> Dict[str, Any]:
        """Parse EVPN Route Type 5: IP Prefix.

        Format: RD(8) + ESI(10) + EthTag(4) + IP_prefix_len(1) + IP_prefix(var) +
                GW_IP_len(1) + GW_IP(var) + Label(3) = 23+ bytes minimum
        """
        validate_data_length(data, 22, "IP Prefix route")

        route = {"type": 5, "name": "IP Prefix"}

        # Parse Route Distinguisher (8 bytes)
        route["rd"] = parse_route_distinguisher(data[0:8])

        # Parse ESI (10 bytes)
        route["esi"] = data[8:18].hex()

        # Parse Ethernet Tag (4 bytes)
        route["eth_tag"], _ = safe_struct_unpack(">I", data, 18)

        offset = 22

        # Parse IP Prefix (variable length)
        if len(data) > offset:
            ip_prefix_len = data[offset]
            route["ip_prefix_length"] = ip_prefix_len
            ip_prefix, offset = parse_ip_prefix(data, offset)
            if ip_prefix:
                route["ip_prefix"] = ip_prefix

            # Parse Gateway IP Address (variable length)
            if len(data) > offset:
                gw_ip_len = data[offset]
                route["gateway_ip_length"] = gw_ip_len
                gateway_ip, offset = parse_variable_length_ip(data, offset)
                if gateway_ip:
                    route["gateway_ip"] = gateway_ip

                # Parse MPLS Label (3 bytes)
                if len(data) >= offset + 3:
                    mpls_info = parse_mpls_label(data, offset)
                    route.update(mpls_info)

        return route