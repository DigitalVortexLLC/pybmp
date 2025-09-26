-- Create extension for TimescaleDB
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Router sessions table
CREATE TABLE IF NOT EXISTS router_sessions (
    id SERIAL PRIMARY KEY,
    router_ip INET NOT NULL,
    router_name VARCHAR(255),
    session_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_end TIMESTAMPTZ,
    status VARCHAR(50) DEFAULT 'active',
    local_port INTEGER,
    peer_as BIGINT,
    peer_bgp_id INET,
    total_messages BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(router_ip, session_start)
);

-- Routes table (main table for BGP routes)
CREATE TABLE IF NOT EXISTS routes (
    id BIGSERIAL,
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    router_ip INET NOT NULL,
    peer_ip INET NOT NULL,
    peer_as BIGINT NOT NULL,
    prefix CIDR NOT NULL,
    prefix_len INTEGER NOT NULL,
    next_hop INET,
    origin VARCHAR(10),
    as_path TEXT,
    communities TEXT,
    extended_communities TEXT,
    large_communities TEXT,
    med INTEGER,
    local_pref INTEGER,
    atomic_aggregate BOOLEAN DEFAULT FALSE,
    aggregator_as BIGINT,
    aggregator_ip INET,
    originator_id INET,
    cluster_list TEXT,

    -- EVPN specific fields
    route_type VARCHAR(50),
    route_distinguisher VARCHAR(50),
    esi VARCHAR(50),
    ethernet_tag_id INTEGER,
    mac_address MACADDR,
    ip_address INET,
    mpls_label1 INTEGER,
    mpls_label2 INTEGER,

    -- AFI/SAFI
    afi INTEGER NOT NULL,
    safi INTEGER NOT NULL,
    family VARCHAR(50) NOT NULL, -- 'IPv4', 'IPv6', 'EVPN'

    -- Tracking fields
    is_withdrawn BOOLEAN DEFAULT FALSE,
    withdrawal_time TIMESTAMPTZ,

    -- Metadata
    raw_message BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (id, time)
);

-- Convert routes table to hypertable
SELECT create_hypertable('routes', 'time', if_not_exists => TRUE);

-- Route history tracking table
CREATE TABLE IF NOT EXISTS route_history (
    id SERIAL PRIMARY KEY,
    prefix CIDR NOT NULL,
    router_ip INET NOT NULL,
    peer_ip INET NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    times_changed INTEGER DEFAULT 0,
    last_next_hop INET,
    previous_next_hop INET,
    total_announcements BIGINT DEFAULT 1,
    total_withdrawals BIGINT DEFAULT 0,
    current_state VARCHAR(20) DEFAULT 'active', -- 'active', 'withdrawn'
    family VARCHAR(50) NOT NULL,
    UNIQUE(prefix, router_ip, peer_ip, family)
);

-- BMP statistics table
CREATE TABLE IF NOT EXISTS bmp_stats (
    id BIGSERIAL,
    time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    router_ip INET NOT NULL,
    peer_ip INET NOT NULL,
    peer_as BIGINT,
    messages_received BIGINT,
    routes_received BIGINT,
    withdrawals_received BIGINT,
    PRIMARY KEY (id, time)
);

-- Convert bmp_stats to hypertable
SELECT create_hypertable('bmp_stats', 'time', if_not_exists => TRUE);

-- Indexes for performance
CREATE INDEX idx_routes_prefix ON routes USING gist(prefix);
CREATE INDEX idx_routes_router_peer ON routes(router_ip, peer_ip);
CREATE INDEX idx_routes_family ON routes(family);
CREATE INDEX idx_routes_withdrawn ON routes(is_withdrawn) WHERE is_withdrawn = TRUE;
CREATE INDEX idx_routes_next_hop ON routes(next_hop);
CREATE INDEX idx_routes_time ON routes(time DESC);

CREATE INDEX idx_route_history_prefix ON route_history USING gist(prefix);
CREATE INDEX idx_route_history_state ON route_history(current_state);
CREATE INDEX idx_route_history_router ON route_history(router_ip);

CREATE INDEX idx_router_sessions_active ON router_sessions(status) WHERE status = 'active';
CREATE INDEX idx_router_sessions_router ON router_sessions(router_ip);

-- Create continuous aggregate for hourly statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS hourly_route_stats
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time) AS hour,
    router_ip,
    peer_ip,
    family,
    COUNT(*) as total_updates,
    COUNT(DISTINCT prefix) as unique_prefixes,
    SUM(CASE WHEN is_withdrawn THEN 1 ELSE 0 END) as withdrawals,
    SUM(CASE WHEN NOT is_withdrawn THEN 1 ELSE 0 END) as announcements
FROM routes
GROUP BY hour, router_ip, peer_ip, family
WITH NO DATA;

-- Refresh policy for continuous aggregate
SELECT add_continuous_aggregate_policy('hourly_route_stats',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE);

-- Data retention policy (configurable, default 90 days)
SELECT add_retention_policy('routes', INTERVAL '90 days', if_not_exists => TRUE);
SELECT add_retention_policy('bmp_stats', INTERVAL '90 days', if_not_exists => TRUE);