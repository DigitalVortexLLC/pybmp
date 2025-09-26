import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import asyncpg

from src.utils.config import Settings

logger = logging.getLogger(__name__)


class DatabasePool:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self) -> None:
        """Create database connection pool."""
        try:
            self.pool = await asyncpg.create_pool(
                host=self.settings.db_host,
                port=self.settings.db_port,
                database=self.settings.db_name,
                user=self.settings.db_user,
                password=self.settings.db_password,
                min_size=10,
                max_size=self.settings.db_pool_size,
                max_queries=50000,
                max_cached_statement_lifetime=300,
                command_timeout=60,
            )
            logger.info("Database connection pool created successfully")
        except Exception as e:
            logger.error(f"Failed to create database connection pool: {e}")
            raise

    async def disconnect(self) -> None:
        """Close database connection pool."""
        if self.pool:
            await self.pool.close()
            logger.info("Database connection pool closed")

    @asynccontextmanager
    async def acquire(self):
        """Acquire a database connection from the pool."""
        async with self.pool.acquire() as connection:
            yield connection

    async def execute(self, query: str, *args) -> str:
        """Execute a query without returning results."""
        async with self.acquire() as conn:
            return await conn.execute(query, *args)

    async def fetch(self, query: str, *args) -> List[asyncpg.Record]:
        """Execute a query and fetch all results."""
        async with self.acquire() as conn:
            return await conn.fetch(query, *args)

    async def fetchrow(self, query: str, *args) -> Optional[asyncpg.Record]:
        """Execute a query and fetch a single row."""
        async with self.acquire() as conn:
            return await conn.fetchrow(query, *args)

    async def insert_route(self, route_data: Dict[str, Any]) -> None:
        """Insert a route record into the database."""
        query = """
            INSERT INTO routes (
                time, router_ip, peer_ip, peer_as, prefix, prefix_len,
                next_hop, origin, as_path, communities, extended_communities,
                large_communities, med, local_pref, atomic_aggregate,
                aggregator_as, aggregator_ip, originator_id, cluster_list,
                route_type, route_distinguisher, esi, ethernet_tag_id,
                mac_address, ip_address, mpls_label1, mpls_label2,
                afi, safi, family, is_withdrawn, withdrawal_time, raw_message
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26,
                $27, $28, $29, $30, $31, $32, $33
            )
        """

        async with self.acquire() as conn:
            await conn.execute(query, *route_data.values())

    async def batch_insert_routes(self, routes: List[Dict[str, Any]]) -> None:
        """Batch insert multiple route records."""
        if not routes:
            return

        query = """
            INSERT INTO routes (
                time, router_ip, peer_ip, peer_as, prefix, prefix_len,
                next_hop, origin, as_path, communities, extended_communities,
                large_communities, med, local_pref, atomic_aggregate,
                aggregator_as, aggregator_ip, originator_id, cluster_list,
                route_type, route_distinguisher, esi, ethernet_tag_id,
                mac_address, ip_address, mpls_label1, mpls_label2,
                afi, safi, family, is_withdrawn, withdrawal_time, raw_message
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                     $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24,
                     $25, $26, $27, $28, $29, $30, $31, $32, $33)
        """

        # Define explicit field order to prevent data corruption
        fields = [
            "time",
            "router_ip",
            "peer_ip",
            "peer_as",
            "prefix",
            "prefix_len",
            "next_hop",
            "origin",
            "as_path",
            "communities",
            "extended_communities",
            "large_communities",
            "med",
            "local_pref",
            "atomic_aggregate",
            "aggregator_as",
            "aggregator_ip",
            "originator_id",
            "cluster_list",
            "route_type",
            "route_distinguisher",
            "esi",
            "ethernet_tag_id",
            "mac_address",
            "ip_address",
            "mpls_label1",
            "mpls_label2",
            "afi",
            "safi",
            "family",
            "is_withdrawn",
            "withdrawal_time",
            "raw_message",
        ]

        async with self.acquire() as conn:
            # Prepare the statement once
            prepared = await conn.prepare(query)

            # Execute batch insert with explicit field ordering
            values = [[r.get(field) for field in fields] for r in routes]
            await prepared.executemany(values)

    async def update_route_history(self, route_data: Dict[str, Any]) -> None:
        """Update route history tracking."""
        query = """
            INSERT INTO route_history (
                prefix, router_ip, peer_ip, first_seen, last_seen,
                last_updated, times_changed, last_next_hop, previous_next_hop,
                total_announcements, total_withdrawals, current_state, family
            ) VALUES ($1, $2, $3, $4, $4, $4, 0, $5, NULL, 1, 0, $6, $7)
            ON CONFLICT (prefix, router_ip, peer_ip, family)
            DO UPDATE SET
                last_seen = EXCLUDED.last_seen,
                last_updated = CASE
                    WHEN route_history.last_next_hop != EXCLUDED.last_next_hop
                    THEN EXCLUDED.last_updated
                    ELSE route_history.last_updated
                END,
                times_changed = CASE
                    WHEN route_history.last_next_hop != EXCLUDED.last_next_hop
                    THEN route_history.times_changed + 1
                    ELSE route_history.times_changed
                END,
                previous_next_hop = CASE
                    WHEN route_history.last_next_hop != EXCLUDED.last_next_hop
                    THEN route_history.last_next_hop
                    ELSE route_history.previous_next_hop
                END,
                last_next_hop = EXCLUDED.last_next_hop,
                total_announcements = route_history.total_announcements + 1,
                current_state = EXCLUDED.current_state
        """

        async with self.acquire() as conn:
            await conn.execute(
                query,
                route_data["prefix"],
                route_data["router_ip"],
                route_data["peer_ip"],
                datetime.now(timezone.utc),
                route_data.get("next_hop"),
                "active" if not route_data.get("is_withdrawn") else "withdrawn",
                route_data["family"],
            )

    async def create_or_update_session(self, session_data: Dict[str, Any]) -> int:
        """Create or update a router session."""
        query = """
            INSERT INTO router_sessions (
                router_ip, router_name, session_start, status,
                local_port, peer_as, peer_bgp_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (router_ip, session_start)
            DO UPDATE SET
                status = EXCLUDED.status,
                updated_at = NOW(),
                total_messages = router_sessions.total_messages + 1
            RETURNING id
        """

        async with self.acquire() as conn:
            result = await conn.fetchrow(
                query,
                session_data["router_ip"],
                session_data.get("router_name"),
                session_data["session_start"],
                session_data.get("status", "active"),
                session_data.get("local_port"),
                session_data.get("peer_as"),
                session_data.get("peer_bgp_id"),
            )
            return result["id"]

    async def close_session(self, router_ip: str, session_id: int) -> None:
        """Close a router session."""
        query = """
            UPDATE router_sessions
            SET status = 'closed',
                session_end = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND router_ip = $2
        """

        async with self.acquire() as conn:
            await conn.execute(query, session_id, router_ip)

    async def update_statistics(self, stats_data: Dict[str, Any]) -> None:
        """Update BMP statistics."""
        query = """
            INSERT INTO bmp_stats (
                time, router_ip, peer_ip, peer_as,
                messages_received, routes_received, withdrawals_received
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        """

        async with self.acquire() as conn:
            await conn.execute(
                query,
                stats_data.get("time", datetime.now(timezone.utc)),
                stats_data["router_ip"],
                stats_data["peer_ip"],
                stats_data.get("peer_as"),
                stats_data.get("messages_received", 0),
                stats_data.get("routes_received", 0),
                stats_data.get("withdrawals_received", 0),
            )

    async def cleanup_old_data(self, retention_days: int) -> int:
        """Remove old data based on retention policy."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)

        # Use parameterized queries to prevent SQL injection
        queries = [
            ("DELETE FROM routes WHERE time < $1", cutoff_date),
            ("DELETE FROM bmp_stats WHERE time < $1", cutoff_date),
        ]

        total_deleted = 0
        async with self.acquire() as conn:
            for query, param in queries:
                result = await conn.execute(query, param)
                # Extract number from result like "DELETE 123"
                if result:
                    try:
                        count = int(result.split()[1]) if len(result.split()) > 1 else 0
                        total_deleted += count
                    except (ValueError, IndexError):
                        # Handle unparseable results
                        logger.warning(f"Could not parse delete result: {result}")
                        continue

        logger.info(f"Cleaned up {total_deleted} old records")
        return total_deleted

    async def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Get all active router sessions."""
        query = """
            SELECT id, router_ip, router_name, session_start,
                   local_port, peer_as, peer_bgp_id, total_messages
            FROM router_sessions
            WHERE status = 'active'
            ORDER BY session_start DESC
        """

        async with self.acquire() as conn:
            rows = await conn.fetch(query)
            return [dict(row) for row in rows]

    async def get_route_summary(self) -> Dict[str, Any]:
        """Get summary statistics about routes."""
        query = """
            SELECT
                COUNT(DISTINCT prefix) as unique_prefixes,
                COUNT(DISTINCT router_ip) as unique_routers,
                COUNT(DISTINCT peer_ip) as unique_peers,
                SUM(CASE WHEN family = 'IPv4' THEN 1 ELSE 0 END) as ipv4_routes,
                SUM(CASE WHEN family = 'IPv6' THEN 1 ELSE 0 END) as ipv6_routes,
                SUM(CASE WHEN family = 'EVPN' THEN 1 ELSE 0 END) as evpn_routes,
                SUM(CASE WHEN is_withdrawn THEN 1 ELSE 0 END) as withdrawn_routes
            FROM routes
            WHERE time >= NOW() - INTERVAL '1 hour'
        """

        async with self.acquire() as conn:
            row = await conn.fetchrow(query)
            return dict(row) if row else {}
