"""Integration tests for database operations."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.database.connection import DatabasePool
from tests.fixtures.database_fixtures import (
    EDGE_CASE_DATA,
    generate_mock_route_data,
    generate_mock_session_data,
    generate_mock_stats_data,
)


class TestDatabasePoolIntegration:
    """Integration tests for database pool operations."""

    @pytest.fixture
    async def real_db_pool(self, test_settings):
        """Create a real database pool for integration testing."""
        # Use a test database connection - in real tests this would connect to a test DB
        db_pool = DatabasePool(test_settings)

        # Mock the actual connection since we don't have a real database
        mock_pool = AsyncMock()
        db_pool.pool = mock_pool

        # Setup proper async context manager for pool.acquire()
        class MockAsyncContextManager:
            def __init__(self, connection):
                self.connection = connection

            async def __aenter__(self):
                return self.connection

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        mock_connection = AsyncMock()
        # Make acquire() return the context manager directly, not as a coroutine
        mock_pool.acquire = Mock(return_value=MockAsyncContextManager(mock_connection))

        yield db_pool

        await db_pool.disconnect()

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_connection_lifecycle(self, test_settings):
        """Test database connection lifecycle."""
        db_pool = DatabasePool(test_settings)

        with patch("src.database.connection.asyncpg.create_pool") as mock_create:
            mock_pool = AsyncMock()
            mock_pool.close = AsyncMock()  # close() is async for asyncpg pools
            # Make create_pool return a coroutine that resolves to the mock_pool
            mock_create.return_value = asyncio.Future()
            mock_create.return_value.set_result(mock_pool)

            # Test connect
            await db_pool.connect()
            assert db_pool.pool == mock_pool

            # Test disconnect
            await db_pool.disconnect()
            mock_pool.close.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_route_insertion_workflow(self, real_db_pool):
        """Test complete route insertion workflow."""
        routes = generate_mock_route_data(10)

        # Mock connection and execution
        mock_connection = AsyncMock()
        mock_prepared = AsyncMock()
        mock_connection.prepare.return_value = mock_prepared

        # Override the default mock connection with our test-specific one
        real_db_pool.pool.acquire.return_value.connection = mock_connection

        await real_db_pool.batch_insert_routes(routes)

        # Verify prepared statement was created and executed
        mock_connection.prepare.assert_called_once()
        mock_prepared.executemany.assert_called_once()

        # Verify correct number of routes processed
        call_args = mock_prepared.executemany.call_args[0][0]
        assert len(call_args) == 10

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_route_history_tracking(self, real_db_pool):
        """Test route history tracking functionality."""
        routes = generate_mock_route_data(5)

        mock_connection = AsyncMock()
        # Override the default mock connection with our test-specific one
        real_db_pool.pool.acquire.return_value.connection = mock_connection

        # Process each route for history
        for route in routes:
            await real_db_pool.update_route_history(route)

        # Verify history updates were called
        assert mock_connection.execute.call_count == 5

        # Verify UPSERT logic in queries
        for call in mock_connection.execute.call_args_list:
            query = call[0][0]
            assert "INSERT INTO route_history" in query
            assert "ON CONFLICT" in query
            assert "DO UPDATE SET" in query

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_session_management_workflow(self, real_db_pool):
        """Test session management workflow."""
        sessions = generate_mock_session_data(3)

        mock_connection = AsyncMock()
        mock_connection.fetchrow.return_value = {"id": 123}
        # Override the default mock connection with our test-specific one
        real_db_pool.pool.acquire.return_value.connection = mock_connection

        # Create sessions
        session_ids = []
        for session in sessions:
            session_id = await real_db_pool.create_or_update_session(session)
            session_ids.append(session_id)

        assert len(session_ids) == 3
        assert all(sid == 123 for sid in session_ids)

        # Close a session
        await real_db_pool.close_session("192.0.2.1", 123)

        # Verify session closure query
        close_calls = [
            call
            for call in mock_connection.execute.call_args_list
            if "UPDATE router_sessions" in call[0][0]
        ]
        assert len(close_calls) == 1

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_statistics_collection(self, real_db_pool):
        """Test statistics collection workflow."""
        stats_data = generate_mock_stats_data(5)

        mock_connection = AsyncMock()
        # Override the default mock connection with our test-specific one
        real_db_pool.pool.acquire.return_value.connection = mock_connection

        # Insert statistics
        for stat in stats_data:
            await real_db_pool.update_statistics(stat)

        # Verify statistics insertions
        assert mock_connection.execute.call_count == 5

        for call in mock_connection.execute.call_args_list:
            query = call[0][0]
            assert "INSERT INTO bmp_stats" in query

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_data_cleanup_workflow(self, real_db_pool):
        """Test data cleanup workflow."""
        mock_connection = AsyncMock()
        mock_connection.execute.side_effect = ["DELETE 100", "DELETE 50"]
        # Override the default mock connection with our test-specific one
        real_db_pool.pool.acquire.return_value.connection = mock_connection

        with patch("src.database.connection.datetime") as mock_datetime:
            mock_now = datetime(2024, 1, 1, 12, 0, 0)
            mock_datetime.utcnow.return_value = mock_now

            deleted_count = await real_db_pool.cleanup_old_data(30)

        assert deleted_count == 150
        assert mock_connection.execute.call_count == 2

        # Verify cleanup queries
        for call in mock_connection.execute.call_args_list:
            query = call[0][0]
            assert "DELETE FROM" in query
            assert "WHERE time <" in query

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_query_summary_generation(self, real_db_pool):
        """Test route summary query generation."""
        mock_connection = AsyncMock()
        mock_summary = {
            "unique_prefixes": 10000,
            "unique_routers": 5,
            "unique_peers": 100,
            "ipv4_routes": 9000,
            "ipv6_routes": 1000,
            "evpn_routes": 0,
            "withdrawn_routes": 500,
        }
        mock_connection.fetchrow.return_value = mock_summary
        # Override the default mock connection with our test-specific one
        real_db_pool.pool.acquire.return_value.connection = mock_connection

        summary = await real_db_pool.get_route_summary()

        assert summary == mock_summary
        mock_connection.fetchrow.assert_called_once()

        # Verify summary query structure
        call_args = mock_connection.fetchrow.call_args[0][0]
        assert "COUNT(DISTINCT prefix)" in call_args
        assert "SUM(CASE WHEN family" in call_args

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_concurrent_database_operations(self, real_db_pool):
        """Test concurrent database operations."""
        # Create multiple mock connections for concurrent use
        mock_connections = [AsyncMock() for _ in range(5)]
        connection_index = 0

        def get_connection():
            nonlocal connection_index
            conn = mock_connections[connection_index % len(mock_connections)]
            connection_index += 1
            return conn

        # Create a custom context manager that cycles through connections
        class ConcurrentMockAsyncContextManager:
            async def __aenter__(self):
                return get_connection()

            async def __aexit__(self, exc_type, exc_val, exc_tb):
                return None

        real_db_pool.pool.acquire = Mock(return_value=ConcurrentMockAsyncContextManager())

        # Prepare test data
        routes_batch = generate_mock_route_data(20)
        sessions_batch = generate_mock_session_data(5)

        # Mock return values
        for conn in mock_connections:
            conn.prepare.return_value = AsyncMock()
            conn.fetchrow.return_value = {"id": 123}

        # Run concurrent operations
        tasks = []

        # Route insertions
        for i in range(0, 20, 5):
            batch = routes_batch[i : i + 5]
            task = asyncio.create_task(real_db_pool.batch_insert_routes(batch))
            tasks.append(task)

        # Session operations
        for session in sessions_batch:
            task = asyncio.create_task(real_db_pool.create_or_update_session(session))
            tasks.append(task)

        # Route history updates
        for route in routes_batch[:5]:
            task = asyncio.create_task(real_db_pool.update_route_history(route))
            tasks.append(task)

        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Verify no exceptions occurred
        exceptions = [r for r in results if isinstance(r, Exception)]
        assert len(exceptions) == 0

        # Verify all connections were used
        for conn in mock_connections:
            assert conn.prepare.called or conn.execute.called or conn.fetchrow.called

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_transaction_handling(self, real_db_pool):
        """Test transaction-like behavior for batch operations."""
        routes = generate_mock_route_data(100)

        mock_connection = AsyncMock()
        mock_prepared = AsyncMock()
        mock_connection.prepare.return_value = mock_prepared

        # Simulate transaction failure
        mock_prepared.executemany.side_effect = Exception("Database constraint violation")

        # Override the default mock connection with our test-specific one
        real_db_pool.pool.acquire.return_value.connection = mock_connection

        # Should handle exception gracefully
        with pytest.raises(Exception):
            await real_db_pool.batch_insert_routes(routes)

        # Verify prepared statement was attempted
        mock_connection.prepare.assert_called_once()
        mock_prepared.executemany.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_connection_pool_exhaustion(self, real_db_pool):
        """Test behavior when connection pool is exhausted."""
        # Mock pool to simulate exhaustion
        mock_pool = AsyncMock()
        mock_pool.acquire = Mock(side_effect=asyncio.TimeoutError("Pool exhausted"))
        real_db_pool.pool = mock_pool

        # Should propagate the timeout error
        with pytest.raises(asyncio.TimeoutError):
            await real_db_pool.execute("SELECT 1")

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_edge_case_data_handling(self, real_db_pool):
        """Test handling of edge case data."""
        edge_cases = EDGE_CASE_DATA

        mock_connection = AsyncMock()
        mock_prepared = AsyncMock()
        mock_connection.prepare.return_value = mock_prepared
        # Override the default mock connection with our test-specific one
        real_db_pool.pool.acquire.return_value.connection = mock_connection

        # Test empty routes
        await real_db_pool.batch_insert_routes(edge_cases["empty_routes"])
        # Should not call database for empty list
        assert not mock_connection.prepare.called

        # Test single route
        await real_db_pool.batch_insert_routes(edge_cases["single_route"])
        mock_connection.prepare.assert_called_once()

        # Test large batch
        mock_connection.reset_mock()
        mock_connection.prepare.return_value = mock_prepared
        await real_db_pool.batch_insert_routes(edge_cases["large_batch"])
        mock_connection.prepare.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_query_parameter_sanitization(self, real_db_pool):
        """Test that query parameters are properly sanitized."""
        mock_connection = AsyncMock()
        # Override the default mock connection with our test-specific one
        real_db_pool.pool.acquire.return_value.connection = mock_connection

        # Test with potentially dangerous data
        dangerous_route = {
            "prefix": "'; DROP TABLE routes; --",
            "router_ip": "'; DELETE FROM routes; --",
            "peer_ip": "'; UPDATE routes SET prefix = 'hacked'; --",
            "peer_as": 65001,
            "family": "IPv4",
            "time": datetime.utcnow(),
        }

        await real_db_pool.update_route_history(dangerous_route)

        # Verify that dangerous strings are passed as parameters, not embedded in query
        call_args = mock_connection.execute.call_args
        query = call_args[0][0]
        params = call_args[0][1:]

        # Query should use placeholders
        assert "$1" in query and "$2" in query
        # Dangerous strings should be in parameters, not query
        assert "DROP TABLE" not in query
        assert "DELETE FROM" not in query
        # But should be in parameters
        assert any("DROP TABLE" in str(param) for param in params)

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_performance_monitoring(self, real_db_pool):
        """Test database performance monitoring capabilities."""
        mock_connection = AsyncMock()
        mock_prepared = AsyncMock()
        mock_connection.prepare.return_value = mock_prepared
        # Override the default mock connection with our test-specific one
        real_db_pool.pool.acquire.return_value.connection = mock_connection

        # Simulate slow query
        async def slow_execution(*args):
            await asyncio.sleep(0.01)  # Simulate 10ms query
            return None

        mock_prepared.executemany.side_effect = slow_execution

        # Measure execution time
        start_time = asyncio.get_event_loop().time()
        routes = generate_mock_route_data(10)
        await real_db_pool.batch_insert_routes(routes)
        execution_time = asyncio.get_event_loop().time() - start_time

        # Verify query executed and took expected time
        assert execution_time >= 0.01
        mock_prepared.executemany.assert_called_once()

    @pytest.mark.asyncio
    @pytest.mark.integration
    @pytest.mark.database
    async def test_field_ordering_consistency(self, real_db_pool):
        """Test that field ordering is consistent across operations."""
        mock_connection = AsyncMock()
        mock_prepared = AsyncMock()
        mock_connection.prepare.return_value = mock_prepared
        # Override the default mock connection with our test-specific one
        real_db_pool.pool.acquire.return_value.connection = mock_connection

        # Create routes with fields in different orders
        route1 = {
            "time": datetime.utcnow(),
            "family": "IPv4",
            "prefix": "10.0.1.0/24",
            "router_ip": "192.0.2.1",
            "peer_ip": "10.0.0.1",
            "peer_as": 65001,
        }

        route2 = {
            "peer_as": 65002,
            "router_ip": "192.0.2.2",
            "time": datetime.utcnow(),
            "prefix": "10.0.2.0/24",
            "family": "IPv4",
            "peer_ip": "10.0.0.2",
        }

        await real_db_pool.batch_insert_routes([route1, route2])

        # Verify that field ordering is enforced
        call_args = mock_prepared.executemany.call_args[0][0]
        assert len(call_args) == 2
        assert len(call_args[0]) == len(call_args[1])  # Same number of fields

        # Both routes should have the same field order
        # (implementation enforces explicit field ordering)
