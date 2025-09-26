"""Unit tests for parsing utilities."""
import struct

import pytest

from src.bmp.parsing_utils import (
    ParseError,
    parse_ip_prefix,
    parse_mac_address,
    parse_mpls_label,
    parse_route_distinguisher,
    parse_variable_length_ip,
    safe_struct_unpack,
    validate_data_length,
)


class TestParseError:
    """Test ParseError exception."""

    @pytest.mark.unit
    def test_parse_error_creation(self):
        """Test ParseError exception creation."""
        error = ParseError("Test error message")
        assert str(error) == "Test error message"


class TestParseMplsLabel:
    """Test MPLS label parsing."""

    @pytest.mark.unit
    def test_parse_mpls_label_valid(self):
        """Test parsing valid MPLS label."""
        # MPLS Label: Label=1000, EXP=3, S=1
        mpls_field = (1000 << 4) | (3 << 1) | 1
        mpls_bytes = struct.pack(">I", mpls_field)[1:]  # Take last 3 bytes

        result = parse_mpls_label(mpls_bytes)

        assert result["mpls_label"] == 1000
        assert result["mpls_exp"] == 3
        assert result["mpls_s"] == 1

    @pytest.mark.unit
    def test_parse_mpls_label_with_offset(self):
        """Test parsing MPLS label with offset."""
        # Create data with prefix + MPLS label
        prefix = b"prefix"
        mpls_field = (2000 << 4) | (5 << 1) | 0
        mpls_bytes = struct.pack(">I", mpls_field)[1:]
        data = prefix + mpls_bytes

        result = parse_mpls_label(data, offset=len(prefix))

        assert result["mpls_label"] == 2000
        assert result["mpls_exp"] == 5
        assert result["mpls_s"] == 0

    @pytest.mark.unit
    def test_parse_mpls_label_insufficient_data(self):
        """Test parsing MPLS label with insufficient data."""
        with pytest.raises(ParseError, match="Insufficient data for MPLS label"):
            parse_mpls_label(b"ab")  # Only 2 bytes

    @pytest.mark.unit
    def test_parse_mpls_label_insufficient_data_with_offset(self):
        """Test parsing MPLS label with insufficient data after offset."""
        data = b"prefix12"  # Only 2 bytes after prefix
        with pytest.raises(ParseError, match="Insufficient data for MPLS label"):
            parse_mpls_label(data, offset=6)

    @pytest.mark.unit
    def test_parse_mpls_label_zero_values(self):
        """Test parsing MPLS label with zero values."""
        mpls_bytes = bytes(3)  # All zeros
        result = parse_mpls_label(mpls_bytes)

        assert result["mpls_label"] == 0
        assert result["mpls_exp"] == 0
        assert result["mpls_s"] == 0

    @pytest.mark.unit
    def test_parse_mpls_label_max_values(self):
        """Test parsing MPLS label with maximum values."""
        # Max label (20 bits all 1s), max EXP (3 bits all 1s), S=1
        mpls_field = (0xFFFFF << 4) | (0x7 << 1) | 1
        mpls_bytes = struct.pack(">I", mpls_field)[1:]

        result = parse_mpls_label(mpls_bytes)

        assert result["mpls_label"] == 0xFFFFF  # Max 20-bit value
        assert result["mpls_exp"] == 7
        assert result["mpls_s"] == 1


class TestParseRouteDistinguisher:
    """Test Route Distinguisher parsing."""

    @pytest.mark.unit
    def test_parse_rd_type_0(self):
        """Test parsing RD Type 0 (AS:Number)."""
        rd_data = struct.pack(">HHI", 0, 65001, 100)
        result = parse_route_distinguisher(rd_data)
        assert result == "65001:100"

    @pytest.mark.unit
    def test_parse_rd_type_1(self):
        """Test parsing RD Type 1 (IP:Number)."""
        rd_data = struct.pack(">HI", 1, 0x0A000001) + struct.pack(">H", 200)  # 10.0.0.1:200
        result = parse_route_distinguisher(rd_data)
        assert result == "10.0.0.1:200"

    @pytest.mark.unit
    def test_parse_rd_unknown_type(self):
        """Test parsing RD with unknown type."""
        rd_data = struct.pack(">HHI", 99, 65001, 100)  # Unknown type 99
        result = parse_route_distinguisher(rd_data)
        assert result == rd_data.hex()

    @pytest.mark.unit
    def test_parse_rd_insufficient_data(self):
        """Test parsing RD with insufficient data."""
        rd_data = b"short"
        result = parse_route_distinguisher(rd_data)
        assert result == rd_data.hex()

    @pytest.mark.unit
    def test_parse_rd_type_0_zero_values(self):
        """Test parsing RD Type 0 with zero values."""
        rd_data = struct.pack(">HHI", 0, 0, 0)
        result = parse_route_distinguisher(rd_data)
        assert result == "0:0"

    @pytest.mark.unit
    def test_parse_rd_type_1_max_values(self):
        """Test parsing RD Type 1 with maximum values."""
        rd_data = struct.pack(">HI", 1, 0xFFFFFFFF) + struct.pack(">H", 65535)
        result = parse_route_distinguisher(rd_data)
        assert result == "255.255.255.255:65535"


class TestParseVariableLengthIp:
    """Test variable length IP parsing."""

    @pytest.mark.unit
    def test_parse_variable_length_ip_ipv4(self):
        """Test parsing IPv4 address."""
        data = struct.pack("B", 32) + struct.pack(">I", 0xC0000201)  # 32 bits + 192.0.2.1
        result, new_offset = parse_variable_length_ip(data, 0)

        assert result == "192.0.2.1"
        assert new_offset == 5

    @pytest.mark.unit
    def test_parse_variable_length_ip_ipv6(self):
        """Test parsing IPv6 address."""
        ipv6_bytes = bytes(
            [
                0x20,
                0x01,
                0x0D,
                0xB8,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
            ]
        )
        data = struct.pack("B", 128) + ipv6_bytes  # 128 bits + 2001:db8::1
        result, new_offset = parse_variable_length_ip(data, 0)

        assert result == "2001:db8::1"
        assert new_offset == 17

    @pytest.mark.unit
    def test_parse_variable_length_ip_zero_length(self):
        """Test parsing IP with zero length."""
        data = struct.pack("B", 0)  # Zero length
        result, new_offset = parse_variable_length_ip(data, 0)

        assert result is None
        assert new_offset == 1

    @pytest.mark.unit
    def test_parse_variable_length_ip_partial(self):
        """Test parsing partial IP address."""
        data = struct.pack("B", 24) + bytes([192, 0, 2])  # 24 bits / /24 prefix
        result, new_offset = parse_variable_length_ip(data, 0)

        assert result == "c00002"  # Hex representation for partial IP
        assert new_offset == 4

    @pytest.mark.unit
    def test_parse_variable_length_ip_insufficient_data_for_length(self):
        """Test parsing IP with insufficient data for length."""
        data = b""  # Empty data
        with pytest.raises(ParseError, match="Insufficient data for IP length"):
            parse_variable_length_ip(data, 0)

    @pytest.mark.unit
    def test_parse_variable_length_ip_insufficient_data_for_address(self):
        """Test parsing IP with insufficient data for address."""
        data = struct.pack("B", 32) + b"abc"  # 32 bits but only 3 bytes
        with pytest.raises(ParseError, match="Insufficient data for IP address"):
            parse_variable_length_ip(data, 0)

    @pytest.mark.unit
    def test_parse_variable_length_ip_invalid_ipv4(self):
        """Test parsing invalid IPv4 data."""
        data = struct.pack("B", 32) + b"abcd"  # Valid IPv4 bytes (97.98.99.100)
        result, new_offset = parse_variable_length_ip(data, 0)

        assert result == "97.98.99.100"  # Valid IPv4 from bytes "abcd"
        assert new_offset == 5

    @pytest.mark.unit
    def test_parse_variable_length_ip_invalid_ipv6(self):
        """Test parsing invalid IPv6 data."""
        data = struct.pack("B", 128) + b"invalid_ipv6_data"  # IPv6 data (18 chars is long enough)
        result, new_offset = parse_variable_length_ip(data, 0)

        # Should return formatted IPv6 address (even if non-standard)
        assert result == "696e:7661:6c69:645f:6970:7636:5f64:6174"
        assert new_offset == 17


class TestParseIpPrefix:
    """Test IP prefix parsing."""

    @pytest.mark.unit
    def test_parse_ip_prefix_ipv4(self):
        """Test parsing IPv4 prefix."""
        data = struct.pack("B", 24) + bytes([192, 0, 2])  # /24 prefix
        result, new_offset = parse_ip_prefix(data, 0)

        assert result == "192.0.2.0/24"
        assert new_offset == 4

    @pytest.mark.unit
    def test_parse_ip_prefix_ipv6(self):
        """Test parsing IPv6 prefix."""
        prefix_bytes = bytes(
            [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00]
        )  # First 8 bytes for /64
        data = struct.pack("B", 64) + prefix_bytes
        result, new_offset = parse_ip_prefix(data, 0)

        assert result == "2001:db8::/64"
        assert new_offset == 9

    @pytest.mark.unit
    def test_parse_ip_prefix_zero_length(self):
        """Test parsing prefix with zero length."""
        data = struct.pack("B", 0)  # Zero length
        result, new_offset = parse_ip_prefix(data, 0)

        assert result is None
        assert new_offset == 1

    @pytest.mark.unit
    def test_parse_ip_prefix_host_route(self):
        """Test parsing host route (/32 for IPv4)."""
        data = struct.pack("B", 32) + struct.pack(">I", 0xC0000201)  # 192.0.2.1/32
        result, new_offset = parse_ip_prefix(data, 0)

        assert result == "192.0.2.1/32"
        assert new_offset == 5

    @pytest.mark.unit
    def test_parse_ip_prefix_insufficient_data_for_length(self):
        """Test parsing prefix with insufficient data for length."""
        data = b""  # Empty data
        with pytest.raises(ParseError, match="Insufficient data for prefix length"):
            parse_ip_prefix(data, 0)

    @pytest.mark.unit
    def test_parse_ip_prefix_insufficient_data_for_prefix(self):
        """Test parsing prefix with insufficient data for prefix."""
        data = struct.pack("B", 24) + b"ab"  # /24 needs 3 bytes but only 2 provided
        with pytest.raises(ParseError, match="Insufficient data for IP prefix"):
            parse_ip_prefix(data, 0)

    @pytest.mark.unit
    def test_parse_ip_prefix_invalid_ipv4_data(self):
        """Test parsing invalid IPv4 prefix data."""
        data = struct.pack("B", 24) + b"xyz"  # Invalid prefix bytes
        result, new_offset = parse_ip_prefix(data, 0)

        # Should handle gracefully and return hex
        assert "/24" in result
        assert new_offset == 4

    @pytest.mark.unit
    def test_parse_ip_prefix_invalid_length(self):
        """Test parsing prefix with invalid length."""
        data = struct.pack("B", 200) + bytes(25)  # Invalid prefix length > 128
        result, new_offset = parse_ip_prefix(data, 0)

        assert "/200" in result
        assert new_offset == 26


class TestParseMacAddress:
    """Test MAC address parsing."""

    @pytest.mark.unit
    def test_parse_mac_address_valid(self):
        """Test parsing valid MAC address."""
        mac_bytes = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        result, new_offset = parse_mac_address(mac_bytes, 0)

        assert result == "aa:bb:cc:dd:ee:ff"
        assert new_offset == 6

    @pytest.mark.unit
    def test_parse_mac_address_with_offset(self):
        """Test parsing MAC address with offset."""
        prefix = b"prefix"
        mac_bytes = bytes([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC])
        data = prefix + mac_bytes

        result, new_offset = parse_mac_address(data, len(prefix))

        assert result == "12:34:56:78:9a:bc"
        assert new_offset == len(prefix) + 6

    @pytest.mark.unit
    def test_parse_mac_address_insufficient_data(self):
        """Test parsing MAC address with insufficient data."""
        data = b"12345"  # Only 5 bytes
        with pytest.raises(ParseError, match="Insufficient data for MAC address"):
            parse_mac_address(data, 0)

    @pytest.mark.unit
    def test_parse_mac_address_zero_values(self):
        """Test parsing MAC address with zero values."""
        mac_bytes = bytes(6)  # All zeros
        result, new_offset = parse_mac_address(mac_bytes, 0)

        assert result == "00:00:00:00:00:00"
        assert new_offset == 6

    @pytest.mark.unit
    def test_parse_mac_address_broadcast(self):
        """Test parsing broadcast MAC address."""
        mac_bytes = bytes([0xFF] * 6)  # All 0xFF
        result, new_offset = parse_mac_address(mac_bytes, 0)

        assert result == "ff:ff:ff:ff:ff:ff"
        assert new_offset == 6


class TestSafeStructUnpack:
    """Test safe struct unpacking."""

    @pytest.mark.unit
    def test_safe_struct_unpack_short(self):
        """Test unpacking short value."""
        data = struct.pack(">H", 12345)
        result, new_offset = safe_struct_unpack(">H", data, 0)

        assert result == 12345
        assert new_offset == 2

    @pytest.mark.unit
    def test_safe_struct_unpack_int(self):
        """Test unpacking int value."""
        data = struct.pack(">I", 0x12345678)
        result, new_offset = safe_struct_unpack(">I", data, 0)

        assert result == 0x12345678
        assert new_offset == 4

    @pytest.mark.unit
    def test_safe_struct_unpack_with_offset(self):
        """Test unpacking with offset."""
        prefix = b"prefix"
        value_data = struct.pack(">H", 54321)
        data = prefix + value_data

        result, new_offset = safe_struct_unpack(">H", data, len(prefix))

        assert result == 54321
        assert new_offset == len(prefix) + 2

    @pytest.mark.unit
    def test_safe_struct_unpack_insufficient_data(self):
        """Test unpacking with insufficient data."""
        data = b"abc"  # Only 3 bytes
        with pytest.raises(ParseError, match="Insufficient data for struct unpack"):
            safe_struct_unpack(">I", data, 0)  # Needs 4 bytes

    @pytest.mark.unit
    def test_safe_struct_unpack_invalid_format(self):
        """Test unpacking with invalid format."""
        data = b"abcd"
        with pytest.raises((ParseError, struct.error)):
            safe_struct_unpack("invalid", data, 0)

    @pytest.mark.unit
    def test_safe_struct_unpack_byte(self):
        """Test unpacking single byte."""
        data = b"A"
        result, new_offset = safe_struct_unpack("B", data, 0)

        assert result == ord("A")
        assert new_offset == 1

    @pytest.mark.unit
    def test_safe_struct_unpack_multiple_values(self):
        """Test unpacking multiple values with tuple format."""
        data = struct.pack(">HH", 0x1234, 0x5678)
        # Note: safe_struct_unpack only returns first value for tuples
        result, new_offset = safe_struct_unpack(">H", data, 0)

        assert result == 0x1234
        assert new_offset == 2


class TestValidateDataLength:
    """Test data length validation."""

    @pytest.mark.unit
    def test_validate_data_length_sufficient(self):
        """Test validation with sufficient data."""
        data = b"hello world"
        validate_data_length(data, 5)  # Should not raise

    @pytest.mark.unit
    def test_validate_data_length_exact(self):
        """Test validation with exact required length."""
        data = b"hello"
        validate_data_length(data, 5)  # Should not raise

    @pytest.mark.unit
    def test_validate_data_length_insufficient(self):
        """Test validation with insufficient data."""
        data = b"hi"
        with pytest.raises(ParseError, match="Insufficient data: need 5 bytes, got 2"):
            validate_data_length(data, 5)

    @pytest.mark.unit
    def test_validate_data_length_custom_description(self):
        """Test validation with custom description."""
        data = b"abc"
        with pytest.raises(ParseError, match="Insufficient test data: need 10 bytes, got 3"):
            validate_data_length(data, 10, "test data")

    @pytest.mark.unit
    def test_validate_data_length_empty_data(self):
        """Test validation with empty data."""
        data = b""
        with pytest.raises(ParseError, match="Insufficient data: need 1 bytes, got 0"):
            validate_data_length(data, 1)

    @pytest.mark.unit
    def test_validate_data_length_zero_requirement(self):
        """Test validation with zero length requirement."""
        data = b""
        validate_data_length(data, 0)  # Should not raise

    @pytest.mark.unit
    def test_validate_data_length_negative_requirement(self):
        """Test validation with negative length requirement."""
        data = b"test"
        validate_data_length(data, -1)  # Should not raise (always satisfied)


class TestParsingUtilsEdgeCases:
    """Test edge cases and integration scenarios."""

    @pytest.mark.unit
    def test_parse_variable_length_ip_boundary_cases(self):
        """Test boundary cases for IP parsing."""
        # Test with 1-bit IP length
        data = struct.pack("B", 1) + b"\x80"  # 1 bit set
        result, new_offset = parse_variable_length_ip(data, 0)
        assert result == "80"  # Hex for partial
        assert new_offset == 2

        # Test with 33-bit IP length (between IPv4 and IPv6)
        data = struct.pack("B", 33) + bytes(5)  # 33 bits = 5 bytes
        result, new_offset = parse_variable_length_ip(data, 0)
        assert result == "0000000000"  # Hex for non-standard length
        assert new_offset == 6

    @pytest.mark.unit
    def test_parse_ip_prefix_boundary_cases(self):
        """Test boundary cases for prefix parsing."""
        # Test /1 prefix
        data = struct.pack("B", 1) + b"\x80"  # /1 prefix
        result, new_offset = parse_ip_prefix(data, 0)
        assert "/1" in result
        assert new_offset == 2

        # Test /129 prefix (invalid for IPv6)
        data = struct.pack("B", 129) + bytes(17)  # 129 bits = 17 bytes
        result, new_offset = parse_ip_prefix(data, 0)
        assert "/129" in result
        assert new_offset == 18

    @pytest.mark.unit
    def test_chained_parsing_operations(self):
        """Test chaining multiple parsing operations."""
        # Build data with multiple components
        rd_data = struct.pack(">HHI", 0, 65001, 100)  # RD
        mpls_field = (1000 << 4) | (3 << 1) | 1
        mpls_data = struct.pack(">I", mpls_field)[1:]  # MPLS label
        ip_data = struct.pack("B", 32) + struct.pack(">I", 0xC0000201)  # IP
        mac_data = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])  # MAC

        combined_data = rd_data + mpls_data + ip_data + mac_data

        # Parse each component in sequence
        offset = 0

        # Parse RD
        rd_result = parse_route_distinguisher(combined_data[offset : offset + 8])
        offset += 8
        assert rd_result == "65001:100"

        # Parse MPLS
        mpls_result = parse_mpls_label(combined_data, offset)
        offset += 3
        assert mpls_result["mpls_label"] == 1000

        # Parse IP
        ip_result, offset = parse_variable_length_ip(combined_data, offset)
        assert ip_result == "192.0.2.1"

        # Parse MAC
        mac_result, offset = parse_mac_address(combined_data, offset)
        assert mac_result == "aa:bb:cc:dd:ee:ff"

        assert offset == len(combined_data)
