import struct
import socket
from typing import Dict, Any, Optional, Tuple, List
from enum import IntEnum
import ipaddress
import logging

logger = logging.getLogger(__name__)


class BMPMessageType(IntEnum):
    ROUTE_MONITORING = 0
    STATISTICS_REPORT = 1
    PEER_DOWN = 2
    PEER_UP = 3
    INITIATION = 4
    TERMINATION = 5
    ROUTE_MIRRORING = 6


class BMPPeerType(IntEnum):
    GLOBAL_INSTANCE = 0
    RD_INSTANCE = 1
    LOCAL_INSTANCE = 2


class BGPMessageType(IntEnum):
    OPEN = 1
    UPDATE = 2
    NOTIFICATION = 3
    KEEPALIVE = 4
    ROUTE_REFRESH = 5


class AFI(IntEnum):
    IPV4 = 1
    IPV6 = 2
    L2VPN = 25


class SAFI(IntEnum):
    UNICAST = 1
    MULTICAST = 2
    MPLS_VPN = 128
    EVPN = 70


class BMPParser:
    def __init__(self):
        self.buffer = b""

    def parse_message(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse a BMP message from raw bytes."""
        if len(data) < 6:
            return None

        # BMP common header
        version = data[0]
        if version != 3:
            logger.warning(f"Unsupported BMP version: {version}")
            return None

        msg_length = struct.unpack(">I", data[1:5])[0]
        msg_type = data[5]

        if len(data) < msg_length:
            return None

        msg_data = data[6:msg_length]

        try:
            if msg_type == BMPMessageType.ROUTE_MONITORING:
                return self._parse_route_monitoring(msg_data)
            elif msg_type == BMPMessageType.PEER_UP:
                return self._parse_peer_up(msg_data)
            elif msg_type == BMPMessageType.PEER_DOWN:
                return self._parse_peer_down(msg_data)
            elif msg_type == BMPMessageType.INITIATION:
                return self._parse_initiation(msg_data)
            elif msg_type == BMPMessageType.TERMINATION:
                return self._parse_termination(msg_data)
            elif msg_type == BMPMessageType.STATISTICS_REPORT:
                return self._parse_stats_report(msg_data)
            else:
                logger.warning(f"Unsupported BMP message type: {msg_type}")
                return None
        except Exception as e:
            logger.error(f"Error parsing BMP message: {e}")
            return None

    def _parse_per_peer_header(self, data: bytes) -> Tuple[Dict[str, Any], int]:
        """Parse BMP per-peer header."""
        if len(data) < 42:
            raise ValueError("Insufficient data for per-peer header")

        header = {}
        header['peer_type'] = data[0]
        flags = data[1]
        header['peer_flags'] = {
            'v_flag': bool(flags & 0x80),  # 0 = IPv4, 1 = IPv6
            'l_flag': bool(flags & 0x40),  # Legacy 2-byte AS
            'a_flag': bool(flags & 0x20),  # AS path
        }

        header['peer_distinguisher'] = data[2:10]

        # Peer address (16 bytes, IPv4 mapped to IPv6)
        if header['peer_flags']['v_flag']:
            header['peer_ip'] = str(ipaddress.IPv6Address(data[10:26]))
        else:
            header['peer_ip'] = str(ipaddress.IPv4Address(data[22:26]))

        header['peer_as'] = struct.unpack(">I", data[26:30])[0]
        header['peer_bgp_id'] = str(ipaddress.IPv4Address(data[30:34]))

        # Timestamps
        header['timestamp_sec'] = struct.unpack(">I", data[34:38])[0]
        header['timestamp_usec'] = struct.unpack(">I", data[38:42])[0]

        return header, 42

    def _parse_route_monitoring(self, data: bytes) -> Dict[str, Any]:
        """Parse Route Monitoring message."""
        peer_header, offset = self._parse_per_peer_header(data)
        bgp_msg = data[offset:]

        result = {
            'type': 'route_monitoring',
            'peer': peer_header,
            'bgp_message': self._parse_bgp_message(bgp_msg)
        }
        return result

    def _parse_bgp_message(self, data: bytes) -> Dict[str, Any]:
        """Parse BGP message."""
        if len(data) < 19:
            raise ValueError("Invalid BGP message")

        # BGP header
        marker = data[0:16]
        length = struct.unpack(">H", data[16:18])[0]
        msg_type = data[18]

        msg_data = data[19:length]

        if msg_type == BGPMessageType.UPDATE:
            return self._parse_bgp_update(msg_data)
        elif msg_type == BGPMessageType.OPEN:
            return self._parse_bgp_open(msg_data)
        else:
            return {'type': msg_type, 'data': msg_data.hex()}

    def _parse_bgp_update(self, data: bytes) -> Dict[str, Any]:
        """Parse BGP UPDATE message."""
        offset = 0
        update = {'type': 'UPDATE'}

        # Withdrawn routes length
        withdrawn_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2

        # Parse withdrawn routes
        if withdrawn_len > 0:
            update['withdrawn'] = self._parse_nlri(data[offset:offset+withdrawn_len])
            offset += withdrawn_len

        # Path attributes length
        path_attr_len = struct.unpack(">H", data[offset:offset+2])[0]
        offset += 2

        # Parse path attributes
        if path_attr_len > 0:
            update['attributes'] = self._parse_path_attributes(data[offset:offset+path_attr_len])
            offset += path_attr_len

        # NLRI (Network Layer Reachability Information)
        if offset < len(data):
            update['nlri'] = self._parse_nlri(data[offset:])

        return update

    def _parse_path_attributes(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse BGP path attributes."""
        attributes = []
        offset = 0

        while offset < len(data):
            if offset + 3 > len(data):
                break

            flags = data[offset]
            attr_type = data[offset + 1]

            optional = bool(flags & 0x80)
            transitive = bool(flags & 0x40)
            partial = bool(flags & 0x20)
            extended = bool(flags & 0x10)

            offset += 2

            if extended:
                if offset + 2 > len(data):
                    break
                attr_len = struct.unpack(">H", data[offset:offset+2])[0]
                offset += 2
            else:
                if offset + 1 > len(data):
                    break
                attr_len = data[offset]
                offset += 1

            if offset + attr_len > len(data):
                break

            attr_data = data[offset:offset + attr_len]
            offset += attr_len

            attr = {
                'type': attr_type,
                'flags': {
                    'optional': optional,
                    'transitive': transitive,
                    'partial': partial,
                    'extended': extended
                },
                'value': self._parse_attribute_value(attr_type, attr_data)
            }
            attributes.append(attr)

        return attributes

    def _parse_attribute_value(self, attr_type: int, data: bytes) -> Any:
        """Parse specific BGP attribute values."""
        if attr_type == 1:  # ORIGIN
            return data[0]
        elif attr_type == 2:  # AS_PATH
            return self._parse_as_path(data)
        elif attr_type == 3:  # NEXT_HOP
            return str(ipaddress.IPv4Address(data))
        elif attr_type == 4:  # MED
            return struct.unpack(">I", data)[0]
        elif attr_type == 5:  # LOCAL_PREF
            return struct.unpack(">I", data)[0]
        elif attr_type == 6:  # ATOMIC_AGGREGATE
            return True
        elif attr_type == 7:  # AGGREGATOR
            as_num = struct.unpack(">I", data[0:4])[0]
            ip = str(ipaddress.IPv4Address(data[4:8]))
            return {'as': as_num, 'ip': ip}
        elif attr_type == 8:  # COMMUNITIES
            return self._parse_communities(data)
        elif attr_type == 14:  # MP_REACH_NLRI
            return self._parse_mp_reach_nlri(data)
        elif attr_type == 15:  # MP_UNREACH_NLRI
            return self._parse_mp_unreach_nlri(data)
        elif attr_type == 16:  # EXTENDED_COMMUNITIES
            return self._parse_extended_communities(data)
        elif attr_type == 32:  # LARGE_COMMUNITIES
            return self._parse_large_communities(data)
        else:
            return data.hex()

    def _parse_as_path(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse AS_PATH attribute."""
        segments = []
        offset = 0

        while offset < len(data):
            if offset + 2 > len(data):
                break

            seg_type = data[offset]
            seg_len = data[offset + 1]
            offset += 2

            if offset + seg_len * 4 > len(data):
                break

            as_numbers = []
            for i in range(seg_len):
                as_num = struct.unpack(">I", data[offset:offset+4])[0]
                as_numbers.append(as_num)
                offset += 4

            segments.append({
                'type': 'AS_SET' if seg_type == 1 else 'AS_SEQUENCE',
                'as_numbers': as_numbers
            })

        return segments

    def _parse_communities(self, data: bytes) -> List[str]:
        """Parse COMMUNITIES attribute."""
        communities = []
        for i in range(0, len(data), 4):
            if i + 4 <= len(data):
                comm = struct.unpack(">HH", data[i:i+4])
                communities.append(f"{comm[0]}:{comm[1]}")
        return communities

    def _parse_extended_communities(self, data: bytes) -> List[str]:
        """Parse EXTENDED_COMMUNITIES attribute."""
        communities = []
        for i in range(0, len(data), 8):
            if i + 8 <= len(data):
                # Simple hex representation for now
                communities.append(data[i:i+8].hex())
        return communities

    def _parse_large_communities(self, data: bytes) -> List[str]:
        """Parse LARGE_COMMUNITIES attribute."""
        communities = []
        for i in range(0, len(data), 12):
            if i + 12 <= len(data):
                parts = struct.unpack(">III", data[i:i+12])
                communities.append(f"{parts[0]}:{parts[1]}:{parts[2]}")
        return communities

    def _parse_mp_reach_nlri(self, data: bytes) -> Dict[str, Any]:
        """Parse MP_REACH_NLRI attribute."""
        if len(data) < 5:
            return {}

        afi = struct.unpack(">H", data[0:2])[0]
        safi = data[2]
        nh_len = data[3]

        offset = 4
        next_hop = None
        if nh_len > 0:
            nh_data = data[offset:offset+nh_len]
            if afi == AFI.IPV4:
                next_hop = str(ipaddress.IPv4Address(nh_data[:4]))
            elif afi == AFI.IPV6:
                next_hop = str(ipaddress.IPv6Address(nh_data[:16]))
            offset += nh_len

        # Skip reserved byte
        offset += 1

        nlri = []
        if offset < len(data):
            if safi == SAFI.EVPN:
                nlri = self._parse_evpn_nlri(data[offset:])
            else:
                nlri = self._parse_nlri(data[offset:], afi)

        return {
            'afi': afi,
            'safi': safi,
            'next_hop': next_hop,
            'nlri': nlri
        }

    def _parse_mp_unreach_nlri(self, data: bytes) -> Dict[str, Any]:
        """Parse MP_UNREACH_NLRI attribute."""
        if len(data) < 3:
            return {}

        afi = struct.unpack(">H", data[0:2])[0]
        safi = data[2]

        nlri = []
        if len(data) > 3:
            if safi == SAFI.EVPN:
                nlri = self._parse_evpn_nlri(data[3:])
            else:
                nlri = self._parse_nlri(data[3:], afi)

        return {
            'afi': afi,
            'safi': safi,
            'withdrawn': nlri
        }

    def _parse_nlri(self, data: bytes, afi: int = AFI.IPV4) -> List[str]:
        """Parse NLRI (Network Layer Reachability Information)."""
        nlri = []
        offset = 0

        while offset < len(data):
            if offset >= len(data):
                break

            prefix_len = data[offset]
            offset += 1

            prefix_bytes = (prefix_len + 7) // 8
            if offset + prefix_bytes > len(data):
                break

            prefix_data = data[offset:offset + prefix_bytes]
            offset += prefix_bytes

            # Pad to full length
            if afi == AFI.IPV6:
                padded = prefix_data + b'\x00' * (16 - len(prefix_data))
                prefix = ipaddress.IPv6Network((padded, prefix_len))
            else:
                padded = prefix_data + b'\x00' * (4 - len(prefix_data))
                prefix = ipaddress.IPv4Network((padded, prefix_len))

            nlri.append(str(prefix))

        return nlri

    def _parse_evpn_nlri(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse EVPN NLRI."""
        nlri = []
        offset = 0

        while offset < len(data):
            if offset + 2 > len(data):
                break

            # EVPN NLRI format: Type (1 byte) + Length (2 bytes) + Value
            route_type = data[offset]
            route_len = struct.unpack(">H", data[offset+1:offset+3])[0]
            offset += 3

            if offset + route_len > len(data):
                break

            route_data = data[offset:offset + route_len]
            offset += route_len

            evpn_route = self._parse_evpn_route(route_type, route_data)
            if evpn_route:
                nlri.append(evpn_route)

        return nlri

    def _parse_evpn_route(self, route_type: int, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse specific EVPN route types."""
        route = {'type': route_type}

        try:
            if route_type == 1:  # Ethernet Auto-Discovery
                route['name'] = 'Ethernet Auto-Discovery'
                # Parse RD, ESI, Ethernet Tag, MPLS Label
            elif route_type == 2:  # MAC/IP Advertisement
                route['name'] = 'MAC/IP Advertisement'
                if len(data) >= 25:
                    # Parse RD (8 bytes)
                    route['rd'] = self._parse_route_distinguisher(data[0:8])
                    # ESI (10 bytes)
                    route['esi'] = data[8:18].hex()
                    # Ethernet Tag (4 bytes)
                    route['eth_tag'] = struct.unpack(">I", data[18:22])[0]
                    # MAC length (1 byte)
                    mac_len = data[22]
                    if mac_len == 48 and len(data) >= 29:
                        # MAC address (6 bytes)
                        route['mac'] = ':'.join(f'{b:02x}' for b in data[23:29])
            elif route_type == 3:  # Inclusive Multicast Ethernet Tag
                route['name'] = 'Inclusive Multicast'
            elif route_type == 4:  # Ethernet Segment
                route['name'] = 'Ethernet Segment'
            elif route_type == 5:  # IP Prefix
                route['name'] = 'IP Prefix'

            return route
        except Exception as e:
            logger.error(f"Error parsing EVPN route type {route_type}: {e}")
            return None

    def _parse_route_distinguisher(self, data: bytes) -> str:
        """Parse Route Distinguisher."""
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

    def _parse_peer_up(self, data: bytes) -> Dict[str, Any]:
        """Parse PEER_UP message."""
        peer_header, offset = self._parse_per_peer_header(data)

        # Local address (16 bytes)
        local_ip = str(ipaddress.IPv6Address(data[offset:offset+16]))
        offset += 16

        # Local port and remote port
        local_port = struct.unpack(">H", data[offset:offset+2])[0]
        remote_port = struct.unpack(">H", data[offset+2:offset+4])[0]
        offset += 4

        # Sent and received OPEN messages
        sent_open = self._parse_bgp_message(data[offset:])

        return {
            'type': 'peer_up',
            'peer': peer_header,
            'local_ip': local_ip,
            'local_port': local_port,
            'remote_port': remote_port,
            'sent_open': sent_open
        }

    def _parse_peer_down(self, data: bytes) -> Dict[str, Any]:
        """Parse PEER_DOWN message."""
        peer_header, offset = self._parse_per_peer_header(data)

        reason = data[offset] if offset < len(data) else 0

        return {
            'type': 'peer_down',
            'peer': peer_header,
            'reason': reason
        }

    def _parse_initiation(self, data: bytes) -> Dict[str, Any]:
        """Parse INITIATION message."""
        tlvs = self._parse_tlvs(data)
        return {
            'type': 'initiation',
            'information': tlvs
        }

    def _parse_termination(self, data: bytes) -> Dict[str, Any]:
        """Parse TERMINATION message."""
        tlvs = self._parse_tlvs(data)
        return {
            'type': 'termination',
            'information': tlvs
        }

    def _parse_stats_report(self, data: bytes) -> Dict[str, Any]:
        """Parse STATISTICS_REPORT message."""
        peer_header, offset = self._parse_per_peer_header(data)

        # Stats count
        stats_count = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4

        stats = []
        for _ in range(stats_count):
            if offset + 4 > len(data):
                break

            stat_type = struct.unpack(">H", data[offset:offset+2])[0]
            stat_len = struct.unpack(">H", data[offset+2:offset+4])[0]
            offset += 4

            if offset + stat_len > len(data):
                break

            stat_data = data[offset:offset+stat_len]
            offset += stat_len

            if stat_len == 4:
                value = struct.unpack(">I", stat_data)[0]
            elif stat_len == 8:
                value = struct.unpack(">Q", stat_data)[0]
            else:
                value = stat_data.hex()

            stats.append({
                'type': stat_type,
                'value': value
            })

        return {
            'type': 'stats_report',
            'peer': peer_header,
            'stats': stats
        }

    def _parse_tlvs(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse TLV (Type-Length-Value) fields."""
        tlvs = []
        offset = 0

        while offset < len(data):
            if offset + 4 > len(data):
                break

            tlv_type = struct.unpack(">H", data[offset:offset+2])[0]
            tlv_len = struct.unpack(">H", data[offset+2:offset+4])[0]
            offset += 4

            if offset + tlv_len > len(data):
                break

            tlv_value = data[offset:offset+tlv_len]
            offset += tlv_len

            if tlv_type in [0, 1, 2]:  # String types
                value = tlv_value.decode('utf-8', errors='replace')
            else:
                value = tlv_value.hex()

            tlvs.append({
                'type': tlv_type,
                'value': value
            })

        return tlvs

    def _parse_bgp_open(self, data: bytes) -> Dict[str, Any]:
        """Parse BGP OPEN message."""
        if len(data) < 10:
            return {'type': 'OPEN', 'error': 'Invalid message length'}

        version = data[0]
        my_as = struct.unpack(">H", data[1:3])[0]
        hold_time = struct.unpack(">H", data[3:5])[0]
        bgp_id = str(ipaddress.IPv4Address(data[5:9]))
        opt_len = data[9]

        capabilities = []
        if opt_len > 0 and len(data) >= 10 + opt_len:
            capabilities = self._parse_capabilities(data[10:10+opt_len])

        return {
            'type': 'OPEN',
            'version': version,
            'as': my_as,
            'hold_time': hold_time,
            'bgp_id': bgp_id,
            'capabilities': capabilities
        }

    def _parse_capabilities(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse BGP capabilities."""
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

            cap_value = data[offset:offset + cap_len]
            offset += cap_len

            capabilities.append({
                'code': cap_code,
                'value': cap_value.hex()
            })

        return capabilities