"""BMP message fixtures for testing."""
import struct
from typing import Dict, List, Any


class BMPMessageBuilder:
    """Builder for creating valid BMP messages for testing."""

    @staticmethod
    def create_bmp_header(msg_type: int, length: int) -> bytes:
        """Create BMP common header."""
        version = 3
        return struct.pack(">BIB", version, length, msg_type)

    @staticmethod
    def create_per_peer_header(
        peer_type: int = 0,
        peer_flags: int = 0,
        peer_ip: str = "192.0.2.1",
        peer_as: int = 65001,
        peer_bgp_id: str = "192.0.2.1",
        timestamp_sec: int = 1704110400,
        timestamp_usec: int = 0
    ) -> bytes:
        """Create BMP per-peer header."""
        peer_distinguisher = b'\x00' * 8

        # Convert IP to 16-byte format (IPv4 mapped to IPv6)
        if '.' in peer_ip:  # IPv4
            ip_bytes = b'\x00' * 10 + b'\xff\xff' + struct.pack(">I",
                sum(int(octet) << (8 * (3 - i)) for i, octet in enumerate(peer_ip.split('.')))
            )
        else:  # IPv6
            import ipaddress
            ip_bytes = ipaddress.IPv6Address(peer_ip).packed

        bgp_id_bytes = struct.pack(">I",
            sum(int(octet) << (8 * (3 - i)) for i, octet in enumerate(peer_bgp_id.split('.')))
        )

        return struct.pack(
            ">BB8s16sII8sII",
            peer_type,
            peer_flags,
            peer_distinguisher,
            ip_bytes,
            peer_as,
            bgp_id_bytes,
            timestamp_sec,
            timestamp_usec
        )

    @staticmethod
    def create_bgp_header(msg_type: int, length: int) -> bytes:
        """Create BGP message header."""
        marker = b'\xff' * 16
        return marker + struct.pack(">HB", length, msg_type)

    @staticmethod
    def create_bgp_update(
        withdrawn: List[str] = None,
        path_attrs: List[Dict] = None,
        nlri: List[str] = None
    ) -> bytes:
        """Create BGP UPDATE message."""
        withdrawn = withdrawn or []
        path_attrs = path_attrs or []
        nlri = nlri or []

        # Withdrawn routes (simplified - just length for now)
        withdrawn_data = b''
        for prefix in withdrawn:
            # Simplified NLRI encoding
            prefix_len = int(prefix.split('/')[1])
            withdrawn_data += struct.pack(">B", prefix_len)
            # Add prefix bytes (simplified)
            withdrawn_data += b'\x0a\x00\x01'  # 10.0.1.0

        withdrawn_len = len(withdrawn_data)

        # Path attributes (simplified)
        attr_data = b''
        for attr in path_attrs:
            attr_type = attr['type']
            attr_value = attr['value']

            if attr_type == 1:  # ORIGIN
                attr_data += struct.pack(">BBB", 0x40, 1, attr_value)
            elif attr_type == 2:  # AS_PATH
                # Simplified AS_PATH
                attr_data += struct.pack(">BB", 0x40, 2)
                as_path_data = struct.pack(">BB", 2, 2)  # AS_SEQUENCE, length 2
                as_path_data += struct.pack(">II", 65001, 65002)
                attr_data += struct.pack(">B", len(as_path_data)) + as_path_data
            elif attr_type == 3:  # NEXT_HOP
                next_hop_bytes = struct.pack(">I",
                    sum(int(octet) << (8 * (3 - i)) for i, octet in enumerate(attr_value.split('.')))
                )
                attr_data += struct.pack(">BBB", 0x40, 3, 4) + next_hop_bytes

        attr_len = len(attr_data)

        # NLRI (simplified)
        nlri_data = b''
        for prefix in nlri:
            prefix_len = int(prefix.split('/')[1])
            nlri_data += struct.pack(">B", prefix_len)
            # Add prefix bytes (simplified for 10.0.x.0/24)
            ip_parts = prefix.split('/')[0].split('.')
            nlri_data += bytes([int(ip_parts[0]), int(ip_parts[1]), int(ip_parts[2])])

        # Construct UPDATE message
        update_data = struct.pack(">H", withdrawn_len)
        update_data += withdrawn_data
        update_data += struct.pack(">H", attr_len)
        update_data += attr_data
        update_data += nlri_data

        # Add BGP header
        bgp_length = 19 + len(update_data)
        bgp_header = BMPMessageBuilder.create_bgp_header(2, bgp_length)  # UPDATE = 2

        return bgp_header + update_data

    @staticmethod
    def create_route_monitoring_message(
        peer_ip: str = "192.0.2.1",
        peer_as: int = 65001,
        nlri: List[str] = None
    ) -> bytes:
        """Create route monitoring BMP message."""
        nlri = nlri or ["10.0.1.0/24"]

        # Create per-peer header
        peer_header = BMPMessageBuilder.create_per_peer_header(
            peer_ip=peer_ip,
            peer_as=peer_as
        )

        # Create BGP UPDATE message
        path_attrs = [
            {'type': 1, 'value': 0},  # ORIGIN: IGP
            {'type': 2, 'value': [65001, 65002]},  # AS_PATH
            {'type': 3, 'value': '192.0.2.2'}  # NEXT_HOP
        ]
        bgp_update = BMPMessageBuilder.create_bgp_update(
            path_attrs=path_attrs,
            nlri=nlri
        )

        # Combine data
        msg_data = peer_header + bgp_update

        # Create BMP header
        msg_length = 6 + len(msg_data)
        bmp_header = BMPMessageBuilder.create_bmp_header(0, msg_length)  # ROUTE_MONITORING = 0

        return bmp_header + msg_data

    @staticmethod
    def create_peer_up_message(
        peer_ip: str = "192.0.2.1",
        peer_as: int = 65001,
        local_ip: str = "192.0.2.100"
    ) -> bytes:
        """Create peer up BMP message."""
        # Create per-peer header
        peer_header = BMPMessageBuilder.create_per_peer_header(
            peer_ip=peer_ip,
            peer_as=peer_as
        )

        # Local address (16 bytes, IPv4 mapped to IPv6)
        local_ip_bytes = b'\x00' * 10 + b'\xff\xff' + struct.pack(">I",
            sum(int(octet) << (8 * (3 - i)) for i, octet in enumerate(local_ip.split('.')))
        )

        # Local and remote ports
        ports = struct.pack(">HH", 179, 179)

        # Simplified BGP OPEN message
        bgp_open = BMPMessageBuilder.create_bgp_header(1, 29)  # OPEN = 1, length = 29
        bgp_open += struct.pack(">BHHIB", 4, 65000, 180,
            sum(int(octet) << (8 * (3 - i)) for i, octet in enumerate("192.0.2.100".split('.'))),
            0  # No optional parameters
        )

        # Combine data
        msg_data = peer_header + local_ip_bytes + ports + bgp_open

        # Create BMP header
        msg_length = 6 + len(msg_data)
        bmp_header = BMPMessageBuilder.create_bmp_header(3, msg_length)  # PEER_UP = 3

        return bmp_header + msg_data

    @staticmethod
    def create_peer_down_message(
        peer_ip: str = "192.0.2.1",
        peer_as: int = 65001,
        reason: int = 1
    ) -> bytes:
        """Create peer down BMP message."""
        # Create per-peer header
        peer_header = BMPMessageBuilder.create_per_peer_header(
            peer_ip=peer_ip,
            peer_as=peer_as
        )

        # Reason byte
        reason_data = struct.pack(">B", reason)

        # Combine data
        msg_data = peer_header + reason_data

        # Create BMP header
        msg_length = 6 + len(msg_data)
        bmp_header = BMPMessageBuilder.create_bmp_header(2, msg_length)  # PEER_DOWN = 2

        return bmp_header + msg_data

    @staticmethod
    def create_initiation_message(
        system_name: str = "test-router",
        system_descr: str = "Test BMP Implementation"
    ) -> bytes:
        """Create initiation BMP message."""
        # TLV for system description
        descr_tlv = struct.pack(">HH", 0, len(system_descr.encode())) + system_descr.encode()

        # TLV for system name
        name_tlv = struct.pack(">HH", 2, len(system_name.encode())) + system_name.encode()

        msg_data = descr_tlv + name_tlv

        # Create BMP header
        msg_length = 6 + len(msg_data)
        bmp_header = BMPMessageBuilder.create_bmp_header(4, msg_length)  # INITIATION = 4

        return bmp_header + msg_data

    @staticmethod
    def create_termination_message(reason: str = "Session terminated") -> bytes:
        """Create termination BMP message."""
        # TLV for termination reason
        reason_tlv = struct.pack(">HH", 0, len(reason.encode())) + reason.encode()

        msg_data = reason_tlv

        # Create BMP header
        msg_length = 6 + len(msg_data)
        bmp_header = BMPMessageBuilder.create_bmp_header(5, msg_length)  # TERMINATION = 5

        return bmp_header + msg_data

    @staticmethod
    def create_stats_report_message(
        peer_ip: str = "192.0.2.1",
        peer_as: int = 65001,
        stats: List[Dict] = None
    ) -> bytes:
        """Create statistics report BMP message."""
        stats = stats or [
            {'type': 0, 'value': 5},     # Prefixes rejected
            {'type': 7, 'value': 1000},  # Updates received
            {'type': 8, 'value': 50}     # Withdrawals received
        ]

        # Create per-peer header
        peer_header = BMPMessageBuilder.create_per_peer_header(
            peer_ip=peer_ip,
            peer_as=peer_as
        )

        # Stats count
        stats_data = struct.pack(">I", len(stats))

        # Add each stat
        for stat in stats:
            stat_type = stat['type']
            stat_value = stat['value']

            if stat_value < 2**32:
                # 32-bit value
                stats_data += struct.pack(">HHI", stat_type, 4, stat_value)
            else:
                # 64-bit value
                stats_data += struct.pack(">HHQ", stat_type, 8, stat_value)

        # Combine data
        msg_data = peer_header + stats_data

        # Create BMP header
        msg_length = 6 + len(msg_data)
        bmp_header = BMPMessageBuilder.create_bmp_header(1, msg_length)  # STATISTICS_REPORT = 1

        return bmp_header + msg_data


# Pre-built test messages
TEST_MESSAGES = {
    'route_monitoring': BMPMessageBuilder.create_route_monitoring_message(),
    'peer_up': BMPMessageBuilder.create_peer_up_message(),
    'peer_down': BMPMessageBuilder.create_peer_down_message(),
    'initiation': BMPMessageBuilder.create_initiation_message(),
    'termination': BMPMessageBuilder.create_termination_message(),
    'stats_report': BMPMessageBuilder.create_stats_report_message(),
}

# Invalid messages for security testing
INVALID_MESSAGES = {
    'wrong_version': b'\x99' + b'\x00\x00\x00\x10' + b'\x00' + b'test',
    'short_header': b'\x03\x00',
    'invalid_length': b'\x03\xFF\xFF\xFF\xFF\x00',
    'zero_length': b'\x03\x00\x00\x00\x00\x00',
    'oversized': b'\x03' + struct.pack(">I", 0x10000000) + b'\x00' + b'X' * 1000,
}

# Edge case messages
EDGE_CASE_MESSAGES = {
    'minimum_valid': b'\x03\x00\x00\x00\x06\x00',  # Minimum 6-byte message
    'empty_route_monitoring': BMPMessageBuilder.create_route_monitoring_message(nlri=[]),
    'large_as_path': BMPMessageBuilder.create_route_monitoring_message(),  # Could be enhanced
    'ipv6_peer': BMPMessageBuilder.create_peer_up_message(peer_ip="2001:db8::1"),
}