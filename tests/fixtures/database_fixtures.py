"""Database test fixtures and mock data."""
from datetime import datetime, timedelta, UTC
from typing import List, Dict, Any
import random


def generate_mock_route_data(count: int = 100) -> List[Dict[str, Any]]:
    """Generate mock route data for database testing."""
    routes = []
    base_time = datetime.now(UTC)

    for i in range(count):
        route = {
            "time": base_time + timedelta(seconds=i),
            "router_ip": f"192.0.2.{(i % 10) + 1}",
            "peer_ip": f"10.{i // 256}.{(i % 256) // 4}.{i % 4}",
            "peer_as": 65000 + (i % 1000),
            "prefix": f"203.0.{i // 256}.0/{24 + (i % 8)}",
            "prefix_len": 24 + (i % 8),
            "next_hop": f"192.0.2.{(i % 10) + 2}",
            "origin": i % 3,
            "as_path": f"[{65000 + i}, {65001 + i}]",
            "communities": f"[{65000}:{i % 100}]" if i % 5 == 0 else None,
            "extended_communities": f"[RT:{65000}:{i}]" if i % 7 == 0 else None,
            "large_communities": f"[{65000}:{i}:{i*10}]" if i % 11 == 0 else None,
            "med": i * 10 if i % 3 == 0 else None,
            "local_pref": 100 + (i % 50),
            "atomic_aggregate": i % 20 == 0,
            "aggregator_as": 65000 + i if i % 15 == 0 else None,
            "aggregator_ip": f"192.0.2.{(i % 10) + 1}" if i % 15 == 0 else None,
            "originator_id": f"192.0.2.{(i % 10) + 1}" if i % 13 == 0 else None,
            "cluster_list": f"[192.0.2.{(i % 5) + 1}]" if i % 17 == 0 else None,
            "route_type": None,
            "route_distinguisher": None,
            "esi": None,
            "ethernet_tag_id": None,
            "mac_address": None,
            "ip_address": None,
            "mpls_label1": None,
            "mpls_label2": None,
            "afi": 1 if i % 20 < 18 else 2,  # Mostly IPv4, some IPv6
            "safi": 1,  # UNICAST
            "family": "IPv4" if i % 20 < 18 else "IPv6",
            "is_withdrawn": i % 10 == 0,  # 10% withdrawals
            "withdrawal_time": base_time + timedelta(seconds=i + 100) if i % 10 == 0 else None,
            "raw_message": None,
        }
        routes.append(route)

    return routes


def generate_mock_evpn_routes(count: int = 50) -> List[Dict[str, Any]]:
    """Generate mock EVPN route data."""
    routes = []
    base_time = datetime.now(UTC)

    for i in range(count):
        route = {
            "time": base_time + timedelta(seconds=i),
            "router_ip": f"192.0.2.{(i % 5) + 1}",
            "peer_ip": f"10.0.{i // 16}.{i % 16}",
            "peer_as": 65000 + (i % 100),
            "prefix": f"evpn:type-{(i % 5) + 1}",
            "prefix_len": 0,
            "next_hop": f"192.0.2.{(i % 5) + 10}",
            "origin": 0,
            "as_path": f"[{65000 + i}]",
            "communities": None,
            "extended_communities": f"[RT:{65000}:{i}]",
            "large_communities": None,
            "med": None,
            "local_pref": 100,
            "atomic_aggregate": False,
            "aggregator_as": None,
            "aggregator_ip": None,
            "originator_id": None,
            "cluster_list": None,
            "route_type": f"Type-{(i % 5) + 1}",
            "route_distinguisher": f"{65000 + i}:{i}",
            "esi": f"{i:020x}",
            "ethernet_tag_id": i % 4096,
            "mac_address": f"{i:02x}:{(i+1):02x}:{(i+2):02x}:{(i+3):02x}:{(i+4):02x}:{(i+5):02x}",
            "ip_address": f"10.0.{i // 256}.{i % 256}" if i % 3 == 0 else None,
            "mpls_label1": 10000 + i,
            "mpls_label2": None,
            "afi": 25,  # L2VPN
            "safi": 70,  # EVPN
            "family": "EVPN",
            "is_withdrawn": i % 15 == 0,  # Fewer EVPN withdrawals
            "withdrawal_time": base_time + timedelta(seconds=i + 200) if i % 15 == 0 else None,
            "raw_message": None,
        }
        routes.append(route)

    return routes


def generate_mock_session_data(count: int = 10) -> List[Dict[str, Any]]:
    """Generate mock router session data."""
    sessions = []
    base_time = datetime.now(UTC)

    for i in range(count):
        session = {
            "id": i + 1,
            "router_ip": f"192.0.2.{i + 1}",
            "router_name": f"router-{i + 1}",
            "session_start": base_time - timedelta(hours=i),
            "session_end": None if i % 8 != 0 else base_time - timedelta(minutes=30),
            "status": "active" if i % 8 != 0 else "closed",
            "local_port": 11019,
            "peer_as": 65000 + i,
            "peer_bgp_id": f"192.0.2.{i + 1}",
            "total_messages": random.randint(1000, 10000),
            "created_at": base_time - timedelta(hours=i),
            "updated_at": base_time - timedelta(minutes=random.randint(1, 60)),
        }
        sessions.append(session)

    return sessions


def generate_mock_stats_data(count: int = 100) -> List[Dict[str, Any]]:
    """Generate mock BMP statistics data."""
    stats = []
    base_time = datetime.now(UTC)

    for i in range(count):
        stat = {
            "id": i + 1,
            "time": base_time - timedelta(minutes=i),
            "router_ip": f"192.0.2.{(i % 5) + 1}",
            "peer_ip": f"10.0.{i // 20}.{i % 20}",
            "peer_as": 65000 + (i % 100),
            "messages_received": random.randint(100, 1000),
            "routes_received": random.randint(1000, 10000),
            "withdrawals_received": random.randint(10, 500),
            "prefixes_rejected": random.randint(0, 50),
            "duplicate_prefixes": random.randint(0, 20),
            "created_at": base_time - timedelta(minutes=i),
        }
        stats.append(stat)

    return stats


def generate_mock_route_history(count: int = 50) -> List[Dict[str, Any]]:
    """Generate mock route history data."""
    history = []
    base_time = datetime.now(UTC)

    for i in range(count):
        record = {
            "id": i + 1,
            "prefix": f"203.0.{i // 16}.0/{24 + (i % 8)}",
            "router_ip": f"192.0.2.{(i % 5) + 1}",
            "peer_ip": f"10.0.{i // 10}.{i % 10}",
            "first_seen": base_time - timedelta(days=random.randint(1, 30)),
            "last_seen": base_time - timedelta(minutes=random.randint(1, 1440)),
            "last_updated": base_time - timedelta(minutes=random.randint(1, 60)),
            "times_changed": random.randint(1, 20),
            "last_next_hop": f"192.0.2.{(i % 5) + 10}",
            "previous_next_hop": f"192.0.2.{(i % 5) + 11}" if i % 3 == 0 else None,
            "total_announcements": random.randint(1, 100),
            "total_withdrawals": random.randint(0, 20),
            "current_state": "active" if i % 10 != 0 else "withdrawn",
            "family": "IPv4" if i % 20 < 18 else "IPv6",
            "created_at": base_time - timedelta(days=random.randint(1, 30)),
            "updated_at": base_time - timedelta(minutes=random.randint(1, 60)),
        }
        history.append(record)

    return history


# Mock database responses for testing
MOCK_DB_RESPONSES = {
    "route_summary": {
        "unique_prefixes": 50000,
        "unique_routers": 10,
        "unique_peers": 500,
        "ipv4_routes": 45000,
        "ipv6_routes": 4800,
        "evpn_routes": 200,
        "withdrawn_routes": 1000,
    },
    "active_sessions": [
        {
            "id": 1,
            "router_ip": "192.0.2.1",
            "router_name": "core-router-1",
            "session_start": datetime.now(UTC) - timedelta(hours=24),
            "local_port": 11019,
            "peer_as": 65001,
            "peer_bgp_id": "192.0.2.1",
            "total_messages": 15000,
        },
        {
            "id": 2,
            "router_ip": "192.0.2.2",
            "router_name": "edge-router-1",
            "session_start": datetime.now(UTC) - timedelta(hours=12),
            "local_port": 11019,
            "peer_as": 65002,
            "peer_bgp_id": "192.0.2.2",
            "total_messages": 8500,
        },
    ],
    "cleanup_result": 1500,
    "session_id": 123,
}


# Test data for edge cases
EDGE_CASE_DATA = {
    "empty_routes": [],
    "single_route": generate_mock_route_data(1),
    "large_batch": generate_mock_route_data(1000),
    "invalid_ip_routes": [
        {
            "time": datetime.now(UTC),
            "router_ip": "invalid-ip",
            "peer_ip": "999.999.999.999",
            "prefix": "invalid-prefix",
            "peer_as": -1,
            "prefix_len": 999,
            "family": "IPv4",
        }
    ],
    "null_values": [
        {
            "time": None,
            "router_ip": None,
            "peer_ip": None,
            "prefix": None,
            "peer_as": None,
            "family": None,
        }
    ],
    "extreme_values": [
        {
            "time": datetime.now(UTC),
            "router_ip": "192.0.2.1",
            "peer_ip": "10.0.0.1",
            "prefix": "0.0.0.0/0",
            "peer_as": 4294967295,  # Max 32-bit AS
            "prefix_len": 32,
            "med": 4294967295,  # Max MED
            "local_pref": 4294967295,  # Max LOCAL_PREF
            "family": "IPv4",
        }
    ],
}
