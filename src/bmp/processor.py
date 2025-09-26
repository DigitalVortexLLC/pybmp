import asyncio
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import ipaddress

from src.bmp.parser import AFI, SAFI

logger = logging.getLogger(__name__)


class RouteProcessor:
    """Process BMP messages and extract route information."""

    def __init__(self, db_pool):
        self.db_pool = db_pool
        self.route_buffer = []
        self.buffer_lock = asyncio.Lock()
        self.stats = {
            'messages_processed': 0,
            'routes_processed': 0,
            'withdrawals_processed': 0,
            'errors': 0
        }

    async def process_message(self, message: Dict[str, Any], router_ip: str) -> None:
        """Process a parsed BMP message."""
        try:
            msg_type = message.get('type')

            if msg_type == 'route_monitoring':
                await self._process_route_monitoring(message, router_ip)
            elif msg_type == 'peer_up':
                await self._process_peer_up(message, router_ip)
            elif msg_type == 'peer_down':
                await self._process_peer_down(message, router_ip)
            elif msg_type == 'stats_report':
                await self._process_stats_report(message, router_ip)
            elif msg_type == 'initiation':
                await self._process_initiation(message, router_ip)
            elif msg_type == 'termination':
                await self._process_termination(message, router_ip)

            self.stats['messages_processed'] += 1

        except Exception as e:
            logger.error(f"Error processing message: {e}")
            self.stats['errors'] += 1

    async def _process_route_monitoring(self, message: Dict[str, Any], router_ip: str) -> None:
        """Process route monitoring message."""
        peer_info = message.get('peer', {})
        bgp_message = message.get('bgp_message', {})

        if bgp_message.get('type') != 'UPDATE':
            return

        peer_ip = peer_info.get('peer_ip')
        peer_as = peer_info.get('peer_as')
        timestamp = self._get_timestamp(peer_info)

        routes = []

        # Process withdrawn routes
        withdrawn = bgp_message.get('withdrawn', [])
        for prefix in withdrawn:
            route = self._create_base_route(
                router_ip, peer_ip, peer_as, prefix, timestamp
            )
            route['is_withdrawn'] = True
            route['withdrawal_time'] = timestamp
            routes.append(route)
            self.stats['withdrawals_processed'] += 1

        # Process announced routes (IPv4/IPv6 unicast)
        nlri = bgp_message.get('nlri', [])
        attributes = self._parse_attributes(bgp_message.get('attributes', []))

        for prefix in nlri:
            route = self._create_route_from_nlri(
                router_ip, peer_ip, peer_as, prefix, attributes, timestamp, AFI.IPV4
            )
            routes.append(route)
            self.stats['routes_processed'] += 1

        # Process MP_REACH_NLRI (IPv6, EVPN, etc.)
        mp_reach = attributes.get('mp_reach_nlri', {})
        if mp_reach:
            await self._process_mp_reach(
                mp_reach, router_ip, peer_ip, peer_as, attributes, timestamp, routes
            )

        # Process MP_UNREACH_NLRI
        mp_unreach = attributes.get('mp_unreach_nlri', {})
        if mp_unreach:
            await self._process_mp_unreach(
                mp_unreach, router_ip, peer_ip, peer_as, timestamp, routes
            )

        # Add routes to buffer
        if routes:
            async with self.buffer_lock:
                self.route_buffer.extend(routes)

            # Flush buffer if it's large enough
            if len(self.route_buffer) >= 100:
                await self.flush_routes()

    async def _process_mp_reach(self, mp_reach: Dict, router_ip: str, peer_ip: str,
                                peer_as: int, attributes: Dict, timestamp: datetime,
                                routes: List[Dict]) -> None:
        """Process MP_REACH_NLRI attribute."""
        afi = mp_reach.get('afi')
        safi = mp_reach.get('safi')
        next_hop = mp_reach.get('next_hop')
        nlri = mp_reach.get('nlri', [])

        if safi == SAFI.EVPN:
            # Process EVPN routes
            for evpn_route in nlri:
                route = self._create_evpn_route(
                    router_ip, peer_ip, peer_as, evpn_route, attributes, timestamp
                )
                route['next_hop'] = next_hop
                routes.append(route)
                self.stats['routes_processed'] += 1

        elif safi == SAFI.UNICAST:
            # Process IPv6 unicast routes
            family = 'IPv6' if afi == AFI.IPV6 else 'IPv4'
            for prefix in nlri:
                route = self._create_route_from_nlri(
                    router_ip, peer_ip, peer_as, prefix, attributes, timestamp, afi
                )
                route['next_hop'] = next_hop
                route['family'] = family
                routes.append(route)
                self.stats['routes_processed'] += 1

    async def _process_mp_unreach(self, mp_unreach: Dict, router_ip: str, peer_ip: str,
                                  peer_as: int, timestamp: datetime,
                                  routes: List[Dict]) -> None:
        """Process MP_UNREACH_NLRI attribute."""
        afi = mp_unreach.get('afi')
        safi = mp_unreach.get('safi')
        withdrawn = mp_unreach.get('withdrawn', [])

        family = self._get_family(afi, safi)

        for item in withdrawn:
            if safi == SAFI.EVPN and isinstance(item, dict):
                # EVPN withdrawal
                route = self._create_evpn_route(
                    router_ip, peer_ip, peer_as, item, {}, timestamp
                )
                route['is_withdrawn'] = True
                route['withdrawal_time'] = timestamp
            else:
                # Regular prefix withdrawal
                route = self._create_base_route(
                    router_ip, peer_ip, peer_as, str(item), timestamp
                )
                route['family'] = family
                route['is_withdrawn'] = True
                route['withdrawal_time'] = timestamp
                route['afi'] = afi
                route['safi'] = safi

            routes.append(route)
            self.stats['withdrawals_processed'] += 1

    def _create_base_route(self, router_ip: str, peer_ip: str, peer_as: int,
                          prefix: str, timestamp: datetime) -> Dict[str, Any]:
        """Create base route dictionary."""
        try:
            network = ipaddress.ip_network(prefix)
            prefix_len = network.prefixlen
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as e:
            logger.warning(f"Invalid prefix format '{prefix}': {e}")
            prefix_len = 0

        return {
            'time': timestamp,
            'router_ip': router_ip,
            'peer_ip': peer_ip,
            'peer_as': peer_as,
            'prefix': prefix,
            'prefix_len': prefix_len,
            'next_hop': None,
            'origin': None,
            'as_path': None,
            'communities': None,
            'extended_communities': None,
            'large_communities': None,
            'med': None,
            'local_pref': None,
            'atomic_aggregate': False,
            'aggregator_as': None,
            'aggregator_ip': None,
            'originator_id': None,
            'cluster_list': None,
            'route_type': None,
            'route_distinguisher': None,
            'esi': None,
            'ethernet_tag_id': None,
            'mac_address': None,
            'ip_address': None,
            'mpls_label1': None,
            'mpls_label2': None,
            'afi': AFI.IPV4,
            'safi': SAFI.UNICAST,
            'family': 'IPv4',
            'is_withdrawn': False,
            'withdrawal_time': None,
            'raw_message': None
        }

    def _create_route_from_nlri(self, router_ip: str, peer_ip: str, peer_as: int,
                                prefix: str, attributes: Dict, timestamp: datetime,
                                afi: int) -> Dict[str, Any]:
        """Create route from NLRI and attributes."""
        route = self._create_base_route(router_ip, peer_ip, peer_as, prefix, timestamp)

        # Update with attributes
        route['next_hop'] = attributes.get('next_hop')
        route['origin'] = attributes.get('origin')
        route['as_path'] = json.dumps(attributes.get('as_path')) if attributes.get('as_path') else None
        route['communities'] = json.dumps(attributes.get('communities')) if attributes.get('communities') else None
        route['extended_communities'] = json.dumps(attributes.get('extended_communities')) if attributes.get('extended_communities') else None
        route['large_communities'] = json.dumps(attributes.get('large_communities')) if attributes.get('large_communities') else None
        route['med'] = attributes.get('med')
        route['local_pref'] = attributes.get('local_pref')
        route['atomic_aggregate'] = attributes.get('atomic_aggregate', False)

        aggregator = attributes.get('aggregator')
        if aggregator:
            route['aggregator_as'] = aggregator.get('as')
            route['aggregator_ip'] = aggregator.get('ip')

        route['originator_id'] = attributes.get('originator_id')
        route['cluster_list'] = json.dumps(attributes.get('cluster_list')) if attributes.get('cluster_list') else None

        route['afi'] = afi
        route['family'] = 'IPv6' if afi == AFI.IPV6 else 'IPv4'

        return route

    def _create_evpn_route(self, router_ip: str, peer_ip: str, peer_as: int,
                          evpn_data: Dict, attributes: Dict, timestamp: datetime) -> Dict[str, Any]:
        """Create EVPN route."""
        # Use a dummy prefix for EVPN routes
        prefix = f"evpn:{evpn_data.get('type', 0)}"

        route = self._create_base_route(router_ip, peer_ip, peer_as, prefix, timestamp)

        # EVPN specific fields
        route['route_type'] = evpn_data.get('name', f"Type-{evpn_data.get('type')}")
        route['route_distinguisher'] = evpn_data.get('rd')
        route['esi'] = evpn_data.get('esi')
        route['ethernet_tag_id'] = evpn_data.get('eth_tag')
        route['mac_address'] = evpn_data.get('mac')
        route['ip_address'] = evpn_data.get('ip')

        # Update with attributes
        route['origin'] = attributes.get('origin')
        route['as_path'] = json.dumps(attributes.get('as_path')) if attributes.get('as_path') else None
        route['communities'] = json.dumps(attributes.get('communities')) if attributes.get('communities') else None
        route['extended_communities'] = json.dumps(attributes.get('extended_communities')) if attributes.get('extended_communities') else None
        route['local_pref'] = attributes.get('local_pref')

        route['afi'] = AFI.L2VPN
        route['safi'] = SAFI.EVPN
        route['family'] = 'EVPN'

        return route

    def _parse_attributes(self, attributes: List[Dict]) -> Dict[str, Any]:
        """Parse BGP attributes into a dictionary."""
        parsed = {}

        for attr in attributes:
            attr_type = attr.get('type')
            value = attr.get('value')

            if attr_type == 1:  # ORIGIN
                parsed['origin'] = value
            elif attr_type == 2:  # AS_PATH
                parsed['as_path'] = value
            elif attr_type == 3:  # NEXT_HOP
                parsed['next_hop'] = value
            elif attr_type == 4:  # MED
                parsed['med'] = value
            elif attr_type == 5:  # LOCAL_PREF
                parsed['local_pref'] = value
            elif attr_type == 6:  # ATOMIC_AGGREGATE
                parsed['atomic_aggregate'] = value
            elif attr_type == 7:  # AGGREGATOR
                parsed['aggregator'] = value
            elif attr_type == 8:  # COMMUNITIES
                parsed['communities'] = value
            elif attr_type == 9:  # ORIGINATOR_ID
                parsed['originator_id'] = value
            elif attr_type == 10:  # CLUSTER_LIST
                parsed['cluster_list'] = value
            elif attr_type == 14:  # MP_REACH_NLRI
                parsed['mp_reach_nlri'] = value
            elif attr_type == 15:  # MP_UNREACH_NLRI
                parsed['mp_unreach_nlri'] = value
            elif attr_type == 16:  # EXTENDED_COMMUNITIES
                parsed['extended_communities'] = value
            elif attr_type == 32:  # LARGE_COMMUNITIES
                parsed['large_communities'] = value

        return parsed

    def _get_family(self, afi: int, safi: int) -> str:
        """Get address family string from AFI/SAFI."""
        if safi == SAFI.EVPN:
            return 'EVPN'
        elif afi == AFI.IPV6:
            return 'IPv6'
        else:
            return 'IPv4'

    def _get_timestamp(self, peer_info: Dict) -> datetime:
        """Get timestamp from peer info."""
        ts_sec = peer_info.get('timestamp_sec', 0)
        ts_usec = peer_info.get('timestamp_usec', 0)
        if ts_sec:
            return datetime.fromtimestamp(ts_sec + ts_usec / 1000000)
        return datetime.utcnow()

    async def _process_peer_up(self, message: Dict[str, Any], router_ip: str) -> None:
        """Process peer up message."""
        peer_info = message.get('peer', {})
        session_data = {
            'router_ip': router_ip,
            'session_start': self._get_timestamp(peer_info),
            'status': 'active',
            'local_port': message.get('local_port'),
            'peer_as': peer_info.get('peer_as'),
            'peer_bgp_id': peer_info.get('peer_bgp_id')
        }

        await self.db_pool.create_or_update_session(session_data)
        logger.info(f"Peer up: {router_ip} -> {peer_info.get('peer_ip')}")

    async def _process_peer_down(self, message: Dict[str, Any], router_ip: str) -> None:
        """Process peer down message."""
        peer_info = message.get('peer', {})
        logger.info(f"Peer down: {router_ip} -> {peer_info.get('peer_ip')}")

        # Mark routes as withdrawn
        routes = []
        route = self._create_base_route(
            router_ip,
            peer_info.get('peer_ip'),
            peer_info.get('peer_as'),
            '0.0.0.0/0',  # Placeholder
            self._get_timestamp(peer_info)
        )
        route['is_withdrawn'] = True
        routes.append(route)

        async with self.buffer_lock:
            self.route_buffer.extend(routes)

    async def _process_stats_report(self, message: Dict[str, Any], router_ip: str) -> None:
        """Process statistics report."""
        peer_info = message.get('peer', {})
        stats = message.get('stats', [])

        stats_data = {
            'time': self._get_timestamp(peer_info),
            'router_ip': router_ip,
            'peer_ip': peer_info.get('peer_ip'),
            'peer_as': peer_info.get('peer_as')
        }

        # Parse statistics
        for stat in stats:
            stat_type = stat.get('type')
            value = stat.get('value')

            # Map known stat types
            if stat_type == 0:  # Prefixes rejected
                stats_data['prefixes_rejected'] = value
            elif stat_type == 1:  # Duplicate prefix
                stats_data['duplicate_prefixes'] = value
            elif stat_type == 7:  # Updates received
                stats_data['routes_received'] = value
            elif stat_type == 8:  # Withdrawals received
                stats_data['withdrawals_received'] = value

        await self.db_pool.update_statistics(stats_data)

    async def _process_initiation(self, message: Dict[str, Any], router_ip: str) -> None:
        """Process initiation message."""
        info = message.get('information', [])
        logger.info(f"BMP session initiated from {router_ip}: {info}")

        session_data = {
            'router_ip': router_ip,
            'session_start': datetime.utcnow(),
            'status': 'active'
        }

        # Extract router name if provided
        for tlv in info:
            if tlv.get('type') == 2:  # sysName
                session_data['router_name'] = tlv.get('value')

        await self.db_pool.create_or_update_session(session_data)

    async def _process_termination(self, message: Dict[str, Any], router_ip: str) -> None:
        """Process termination message."""
        info = message.get('information', [])
        logger.info(f"BMP session terminated from {router_ip}: {info}")

        # Get active session
        sessions = await self.db_pool.get_active_sessions()
        for session in sessions:
            if session['router_ip'] == router_ip:
                await self.db_pool.close_session(router_ip, session['id'])
                break

    async def flush_routes(self) -> None:
        """Flush buffered routes to database."""
        async with self.buffer_lock:
            if not self.route_buffer:
                return

            routes_to_insert = self.route_buffer.copy()
            self.route_buffer.clear()

        try:
            # Batch insert routes
            await self.db_pool.batch_insert_routes(routes_to_insert)

            # Update route history for each route
            for route in routes_to_insert:
                await self.db_pool.update_route_history(route)

            logger.debug(f"Flushed {len(routes_to_insert)} routes to database")

        except Exception as e:
            logger.error(f"Error flushing routes: {e}")
            # Re-add routes to buffer on error
            async with self.buffer_lock:
                self.route_buffer.extend(routes_to_insert)

    def get_stats(self) -> Dict[str, int]:
        """Get processing statistics."""
        return self.stats.copy()