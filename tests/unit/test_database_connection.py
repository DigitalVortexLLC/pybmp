"""Unit tests for database connection layer."""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, call
from contextlib import asynccontextmanager

from src.database.connection import DatabasePool
from tests.fixtures.database_fixtures import (
    generate_mock_route_data,
    generate_mock_session_data,
    MOCK_DB_RESPONSES,
    EDGE_CASE_DATA,
)


class TestDatabasePool:
    """Test database pool functionality."""

    @pytest.mark.unit
    def test_database_pool_initialization(self, test_settings):
        """Test database pool initialization."""
        db_pool = DatabasePool(test_settings)

        assert db_pool.settings == test_settings
        assert db_pool.pool is None

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_connect_success(self, test_settings):
        """Test successful database connection."""
        db_pool = DatabasePool(test_settings)

        with patch("src.database.connection.asyncpg.create_pool") as mock_create_pool:
            mock_pool = AsyncMock()

            async def async_return():
                return mock_pool

            mock_create_pool.return_value = async_return()

            await db_pool.connect()

            assert db_pool.pool == mock_pool
            mock_create_pool.assert_called_once_with(
                host=test_settings.db_host,
                port=test_settings.db_port,
                database=test_settings.db_name,
                user=test_settings.db_user,
                password=test_settings.db_password,
                min_size=10,
                max_size=test_settings.db_pool_size,
                max_queries=50000,
                max_cached_statement_lifetime=300,
                command_timeout=60,
            )

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_connect_failure(self, test_settings):
        """Test database connection failure."""
        db_pool = DatabasePool(test_settings)

        with patch("src.database.connection.asyncpg.create_pool") as mock_create_pool:
            mock_create_pool.side_effect = Exception("Connection failed")

            with pytest.raises(Exception, match="Connection failed"):
                await db_pool.connect()

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_disconnect(self, test_settings):
        """Test database disconnection."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        db_pool.pool = mock_pool

        await db_pool.disconnect()

        mock_pool.close.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_disconnect_no_pool(self, test_settings):
        """Test disconnect when no pool exists."""
        db_pool = DatabasePool(test_settings)

        # Should not raise exception
        await db_pool.disconnect()

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_acquire_context_manager(self, test_settings):
        """Test acquire context manager."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        async with db_pool.acquire() as conn:
            assert conn == mock_connection

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_execute_query(self, test_settings):
        """Test execute query without results."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_connection.execute.return_value = "EXECUTE 1"

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        result = await db_pool.execute("UPDATE table SET col = $1", "value")

        assert result == "EXECUTE 1"
        mock_connection.execute.assert_called_once_with("UPDATE table SET col = $1", "value")

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_fetch_query(self, test_settings):
        """Test fetch query with results."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_records = [{"id": 1, "name": "test"}]
        mock_connection.fetch.return_value = mock_records

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        result = await db_pool.fetch("SELECT * FROM table WHERE id = $1", 1)

        assert result == mock_records
        mock_connection.fetch.assert_called_once_with("SELECT * FROM table WHERE id = $1", 1)

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_fetchrow_query(self, test_settings):
        """Test fetchrow query."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_record = {"id": 1, "name": "test"}
        mock_connection.fetchrow.return_value = mock_record

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        result = await db_pool.fetchrow("SELECT * FROM table WHERE id = $1", 1)

        assert result == mock_record
        mock_connection.fetchrow.assert_called_once_with("SELECT * FROM table WHERE id = $1", 1)

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_insert_route(self, test_settings):
        """Test inserting single route."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        route_data = generate_mock_route_data(1)[0]

        await db_pool.insert_route(route_data)

        mock_connection.execute.assert_called_once()
        call_args = mock_connection.execute.call_args
        assert "INSERT INTO routes" in call_args[0][0]

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_batch_insert_routes(self, test_settings):
        """Test batch inserting routes."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_prepared = AsyncMock()
        mock_connection.prepare.return_value = mock_prepared

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        routes = generate_mock_route_data(5)

        await db_pool.batch_insert_routes(routes)

        mock_connection.prepare.assert_called_once()
        mock_prepared.executemany.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_batch_insert_empty_routes(self, test_settings):
        """Test batch insert with empty routes list."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        db_pool.pool = mock_pool

        await db_pool.batch_insert_routes([])

        # No database calls should be made
        assert not mock_pool.acquire.called

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_update_route_history(self, test_settings):
        """Test updating route history."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        route_data = {
            "prefix": "10.0.1.0/24",
            "router_ip": "192.0.2.1",
            "peer_ip": "10.0.0.1",
            "next_hop": "192.0.2.2",
            "family": "IPv4",
            "is_withdrawn": False,
        }

        with patch("src.database.connection.datetime") as mock_datetime:
            mock_now = datetime(2024, 1, 1, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            await db_pool.update_route_history(route_data)

            mock_connection.execute.assert_called_once()
            call_args = mock_connection.execute.call_args
            assert "INSERT INTO route_history" in call_args[0][0]
            assert "ON CONFLICT" in call_args[0][0]

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_create_or_update_session(self, test_settings):
        """Test creating or updating session."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_connection.fetchrow.return_value = {"id": 123}

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        session_data = {
            "router_ip": "192.0.2.1",
            "router_name": "test-router",
            "session_start": datetime.now(),
            "status": "active",
        }

        result = await db_pool.create_or_update_session(session_data)

        assert result == 123
        mock_connection.fetchrow.assert_called_once()
        call_args = mock_connection.fetchrow.call_args
        assert "INSERT INTO router_sessions" in call_args[0][0]

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_close_session(self, test_settings):
        """Test closing session."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        await db_pool.close_session("192.0.2.1", 123)

        mock_connection.execute.assert_called_once()
        call_args = mock_connection.execute.call_args
        assert "UPDATE router_sessions" in call_args[0][0]
        assert call_args[0][1] == 123
        assert call_args[0][2] == "192.0.2.1"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_update_statistics(self, test_settings):
        """Test updating BMP statistics."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        stats_data = {
            "router_ip": "192.0.2.1",
            "peer_ip": "10.0.0.1",
            "peer_as": 65001,
            "routes_received": 1000,
            "withdrawals_received": 50,
        }

        with patch("src.database.connection.datetime") as mock_datetime:
            mock_now = datetime(2024, 1, 1, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            await db_pool.update_statistics(stats_data)

            mock_connection.execute.assert_called_once()
            call_args = mock_connection.execute.call_args
            assert "INSERT INTO bmp_stats" in call_args[0][0]

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_cleanup_old_data(self, test_settings):
        """Test cleaning up old data."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        # Mock DELETE results
        mock_connection.execute.side_effect = ["DELETE 100", "DELETE 50"]

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        with patch("src.database.connection.datetime") as mock_datetime:
            mock_now = datetime(2024, 1, 1, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            result = await db_pool.cleanup_old_data(30)

            assert result == 150  # 100 + 50
            assert mock_connection.execute.call_count == 2

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_cleanup_old_data_parse_error(self, test_settings):
        """Test cleanup with unparseable result."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_connection.execute.side_effect = ["INVALID RESULT", "DELETE 25"]

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        with patch("src.database.connection.datetime") as mock_datetime:
            mock_now = datetime(2024, 1, 1, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            result = await db_pool.cleanup_old_data(30)

            assert result == 25  # Only the parseable result

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_get_active_sessions(self, test_settings):
        """Test getting active sessions."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_sessions = MOCK_DB_RESPONSES["active_sessions"]
        mock_connection.fetch.return_value = [dict(session) for session in mock_sessions]

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        result = await db_pool.get_active_sessions()

        assert len(result) == len(mock_sessions)
        mock_connection.fetch.assert_called_once()
        call_args = mock_connection.fetch.call_args
        assert "SELECT" in call_args[0][0]
        assert "WHERE status = 'active'" in call_args[0][0]

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_get_route_summary(self, test_settings):
        """Test getting route summary."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_summary = MOCK_DB_RESPONSES["route_summary"]
        mock_connection.fetchrow.return_value = mock_summary

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        result = await db_pool.get_route_summary()

        assert result == mock_summary
        mock_connection.fetchrow.assert_called_once()
        call_args = mock_connection.fetchrow.call_args
        assert "COUNT(DISTINCT prefix)" in call_args[0][0]

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_get_route_summary_no_data(self, test_settings):
        """Test getting route summary with no data."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_connection.fetchrow.return_value = None

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        result = await db_pool.get_route_summary()

        assert result == {}


class TestDatabasePoolEdgeCases:
    """Test edge cases and error conditions."""

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_batch_insert_with_field_ordering(self, test_settings):
        """Test batch insert with explicit field ordering."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_prepared = AsyncMock()
        mock_connection.prepare.return_value = mock_prepared

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        # Create routes with missing fields
        routes = [
            {
                "time": datetime.now(),
                "router_ip": "192.0.2.1",
                "peer_ip": "10.0.0.1",
                "prefix": "10.0.1.0/24",
                "family": "IPv4"
                # Missing many fields
            }
        ]

        await db_pool.batch_insert_routes(routes)

        # Should handle missing fields gracefully
        mock_prepared.executemany.assert_called_once()
        call_args = mock_prepared.executemany.call_args
        values = call_args[0][0]
        assert len(values) == 1
        assert len(values[0]) == 33  # All 33 fields should be present

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_connection_context_manager_exception(self, test_settings):
        """Test connection context manager with exception."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()

        @asynccontextmanager
        async def mock_acquire():
            yield AsyncMock()

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        # Test that exceptions are properly propagated
        with pytest.raises(ValueError):
            async with db_pool.acquire() as conn:
                raise ValueError("Test exception")

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_concurrent_operations(self, test_settings):
        """Test concurrent database operations."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connections = [AsyncMock() for _ in range(5)]

        connection_index = 0

        @asynccontextmanager
        async def mock_acquire():
            nonlocal connection_index
            conn = mock_connections[connection_index % len(mock_connections)]
            connection_index += 1
            yield conn

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        # Run concurrent operations
        tasks = []
        for i in range(10):
            task = asyncio.create_task(db_pool.execute(f"SELECT {i}", i))
            tasks.append(task)

        await asyncio.gather(*tasks)

        # All connections should have been used
        assert all(conn.execute.called for conn in mock_connections)

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_route_history_with_withdrawal(self, test_settings):
        """Test route history with withdrawal."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        route_data = {
            "prefix": "10.0.1.0/24",
            "router_ip": "192.0.2.1",
            "peer_ip": "10.0.0.1",
            "next_hop": "192.0.2.2",
            "family": "IPv4",
            "is_withdrawn": True,
        }

        with patch("src.database.connection.datetime") as mock_datetime:
            mock_now = datetime(2024, 1, 1, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            await db_pool.update_route_history(route_data)

            call_args = mock_connection.execute.call_args
            # Should mark as withdrawn
            assert call_args[0][6] == "withdrawn"

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_statistics_with_default_time(self, test_settings):
        """Test statistics update with default timestamp."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        stats_data = {
            "router_ip": "192.0.2.1",
            "peer_ip": "10.0.0.1"
            # No explicit time provided
        }

        with patch("src.database.connection.datetime") as mock_datetime:
            mock_now = datetime(2024, 1, 1, 12, 0, 0)
            mock_datetime.now.return_value = mock_now

            await db_pool.update_statistics(stats_data)

            call_args = mock_connection.execute.call_args
            # Should use current time as default
            assert call_args[0][1] == mock_now

    @pytest.mark.asyncio
    @pytest.mark.unit
    async def test_session_creation_with_minimal_data(self, test_settings):
        """Test session creation with minimal required data."""
        db_pool = DatabasePool(test_settings)
        mock_pool = AsyncMock()
        mock_connection = AsyncMock()
        mock_connection.fetchrow.return_value = {"id": 456}

        @asynccontextmanager
        async def mock_acquire():
            yield mock_connection

        mock_pool.acquire = mock_acquire
        db_pool.pool = mock_pool

        session_data = {
            "router_ip": "192.0.2.1",
            "session_start": datetime.now()
            # Missing optional fields
        }

        result = await db_pool.create_or_update_session(session_data)

        assert result == 456
        call_args = mock_connection.fetchrow.call_args
        # Should handle None values for optional fields
        assert call_args[0][2] is None  # router_name
        assert call_args[0][4] == "active"  # default status
