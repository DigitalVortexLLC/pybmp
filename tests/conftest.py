"""Pytest configuration and shared fixtures."""
import asyncio
import pytest
import os
import tempfile
import shutil
from typing import Dict, Any, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime

# Import application modules
from src.utils.config import Settings
from src.database.connection import DatabasePool
from src.bmp.parser import BMPParser
from src.bmp.processor import RouteProcessor


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_settings() -> Settings:
    """Test settings with secure defaults."""
    return Settings(
        db_host="localhost",
        db_port=5432,
        db_name="test_bmp",
        db_user="test_user",
        db_password="test_password",
        db_pool_size=5,
        bmp_listen_host="127.0.0.1",
        bmp_listen_port=11019,
        bmp_buffer_size=65536,
        bmp_max_connections=10,
        log_level="DEBUG",
        data_retention_days=30,
        batch_size=100,
        batch_timeout_seconds=1
    )


@pytest.fixture
def mock_db_pool():
    """Mock database pool for testing."""
    mock_pool = AsyncMock(spec=DatabasePool)
    mock_pool.connect = AsyncMock()
    mock_pool.disconnect = AsyncMock()
    mock_pool.execute = AsyncMock(return_value="EXECUTE")
    mock_pool.fetch = AsyncMock(return_value=[])
    mock_pool.fetchrow = AsyncMock(return_value=None)
    mock_pool.insert_route = AsyncMock()
    mock_pool.batch_insert_routes = AsyncMock()
    mock_pool.update_route_history = AsyncMock()
    mock_pool.create_or_update_session = AsyncMock(return_value=1)
    mock_pool.close_session = AsyncMock()
    mock_pool.update_statistics = AsyncMock()
    mock_pool.cleanup_old_data = AsyncMock(return_value=0)
    mock_pool.get_active_sessions = AsyncMock(return_value=[])
    mock_pool.get_route_summary = AsyncMock(return_value={})
    return mock_pool


@pytest.fixture
def bmp_parser():
    """BMP parser instance for testing."""
    return BMPParser()


@pytest.fixture
async def route_processor(mock_db_pool):
    """Route processor with mocked database."""
    return RouteProcessor(mock_db_pool)


@pytest.fixture
def temp_directory():
    """Temporary directory for test files."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def mock_env_vars():
    """Mock environment variables for testing."""
    original_env = os.environ.copy()
    test_env = {
        "DB_HOST": "test_host",
        "DB_PORT": "5433",
        "DB_NAME": "test_db",
        "DB_USER": "test_user",
        "DB_PASSWORD": "test_pass",
        "LOG_LEVEL": "DEBUG"
    }
    os.environ.update(test_env)
    yield test_env
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def sample_timestamp():
    """Sample timestamp for testing."""
    return datetime(2024, 1, 1, 12, 0, 0)


@pytest.fixture
def sample_peer_header():
    """Sample BMP peer header data."""
    return {
        'peer_type': 0,
        'peer_flags': {
            'v_flag': False,
            'l_flag': False,
            'a_flag': False
        },
        'peer_distinguisher': b'\x00' * 8,
        'peer_ip': '192.0.2.1',
        'peer_as': 65001,
        'peer_bgp_id': '192.0.2.1',
        'timestamp_sec': 1704110400,
        'timestamp_usec': 0
    }


@pytest.fixture
def sample_bgp_update():
    """Sample BGP UPDATE message data."""
    return {
        'type': 'UPDATE',
        'withdrawn': [],
        'attributes': [
            {
                'type': 1,  # ORIGIN
                'flags': {'optional': False, 'transitive': True, 'partial': False, 'extended': False},
                'value': 0  # IGP
            },
            {
                'type': 2,  # AS_PATH
                'flags': {'optional': False, 'transitive': True, 'partial': False, 'extended': False},
                'value': [{'type': 'AS_SEQUENCE', 'as_numbers': [65001, 65002]}]
            },
            {
                'type': 3,  # NEXT_HOP
                'flags': {'optional': False, 'transitive': True, 'partial': False, 'extended': False},
                'value': '192.0.2.2'
            }
        ],
        'nlri': ['10.0.1.0/24', '10.0.2.0/24']
    }


@pytest.fixture
def sample_route_monitoring_message(sample_peer_header, sample_bgp_update):
    """Sample route monitoring message."""
    return {
        'type': 'route_monitoring',
        'peer': sample_peer_header,
        'bgp_message': sample_bgp_update
    }


@pytest.fixture
def sample_peer_up_message(sample_peer_header):
    """Sample peer up message."""
    return {
        'type': 'peer_up',
        'peer': sample_peer_header,
        'local_ip': '192.0.2.100',
        'local_port': 179,
        'remote_port': 179,
        'sent_open': {
            'type': 'OPEN',
            'version': 4,
            'as': 65000,
            'hold_time': 180,
            'bgp_id': '192.0.2.100',
            'capabilities': []
        }
    }


@pytest.fixture
def sample_peer_down_message(sample_peer_header):
    """Sample peer down message."""
    return {
        'type': 'peer_down',
        'peer': sample_peer_header,
        'reason': 1
    }


@pytest.fixture
def sample_stats_message(sample_peer_header):
    """Sample statistics report message."""
    return {
        'type': 'stats_report',
        'peer': sample_peer_header,
        'stats': [
            {'type': 0, 'value': 5},    # Prefixes rejected
            {'type': 7, 'value': 1000}, # Updates received
            {'type': 8, 'value': 50}    # Withdrawals received
        ]
    }


@pytest.fixture
def sample_initiation_message():
    """Sample initiation message."""
    return {
        'type': 'initiation',
        'information': [
            {'type': 0, 'value': 'Test BMP Implementation'},
            {'type': 1, 'value': 'Version 1.0'},
            {'type': 2, 'value': 'test-router'}
        ]
    }


@pytest.fixture
def sample_termination_message():
    """Sample termination message."""
    return {
        'type': 'termination',
        'information': [
            {'type': 0, 'value': 'Session terminated by user'}
        ]
    }


# Security test fixtures
@pytest.fixture
def malicious_bmp_data():
    """Malicious BMP data for security testing."""
    return {
        # Oversized message
        'oversized_message': b'\x03' + b'\xFF' * 4 + b'\x00' + b'A' * 1000000,

        # Invalid version
        'invalid_version': b'\x99' + b'\x00\x00\x00\x10' + b'\x00' + b'test',

        # Malformed header
        'malformed_header': b'\x03\x00',

        # Buffer overflow attempt
        'buffer_overflow': b'\x03' + (0x10000000).to_bytes(4, 'big') + b'\x00' + b'X' * 1000,

        # Invalid peer header
        'invalid_peer_header': b'\x03' + b'\x00\x00\x00\x30' + b'\x00' + b'X' * 20,
    }


@pytest.fixture
def sql_injection_payloads():
    """SQL injection test payloads."""
    return [
        "'; DROP TABLE routes; --",
        "' OR 1=1 --",
        "'; INSERT INTO routes VALUES (1,2,3); --",
        "1'; EXEC xp_cmdshell('dir'); --",
        "' UNION SELECT password FROM users --"
    ]


@pytest.fixture
def xss_payloads():
    """XSS test payloads for input validation."""
    return [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "'; alert('xss'); //"
    ]


# Rate limiting test fixtures
@pytest.fixture
def rate_limit_test_ips():
    """IP addresses for rate limiting tests."""
    return [
        "192.0.2.1",
        "192.0.2.2",
        "10.0.0.1",
        "172.16.0.1",
        "203.0.113.1"
    ]


# Mock data generators for bulk testing
def generate_mock_routes(count: int = 100) -> list:
    """Generate mock route data for testing."""
    routes = []
    for i in range(count):
        route = {
            'time': datetime.utcnow(),
            'router_ip': f'192.0.2.{i % 10 + 1}',
            'peer_ip': f'10.0.{i // 256}.{i % 256}',
            'peer_as': 65000 + (i % 1000),
            'prefix': f'203.0.{i // 256}.0/{24 + (i % 8)}',
            'prefix_len': 24 + (i % 8),
            'next_hop': f'192.0.2.{(i % 10) + 1}',
            'origin': i % 3,
            'as_path': f'[{65000 + i}, {65001 + i}]',
            'med': i * 10,
            'local_pref': 100 + i,
            'family': 'IPv4',
            'is_withdrawn': i % 10 == 0,
            'afi': 1,
            'safi': 1
        }
        routes.append(route)
    return routes


@pytest.fixture
def mock_route_batch():
    """Batch of mock routes for testing."""
    return generate_mock_routes(50)


# Error simulation fixtures
@pytest.fixture
def network_error_simulation():
    """Simulate network errors for testing."""
    return {
        'connection_reset': ConnectionResetError("Connection reset by peer"),
        'connection_timeout': TimeoutError("Connection timed out"),
        'connection_refused': ConnectionRefusedError("Connection refused"),
        'network_unreachable': OSError("Network is unreachable")
    }


@pytest.fixture
def database_error_simulation():
    """Simulate database errors for testing."""
    return {
        'connection_error': Exception("Database connection failed"),
        'query_timeout': Exception("Query execution timeout"),
        'constraint_violation': Exception("Constraint violation"),
        'deadlock': Exception("Deadlock detected")
    }