# Useful Queries

This section provides ready-to-use SQL queries for common BGP monitoring and analysis tasks. All queries are designed to work with TimescaleDB and take advantage of the hypertable structure for optimal performance.

## Route Analysis Queries

### Routes with High Churn (Most Unstable Routes)

Identify routes that change frequently, indicating potential instability:

```sql
SELECT
    prefix,
    router_ip,
    peer_ip,
    times_changed,
    total_announcements,
    total_withdrawals,
    last_updated,
    (total_announcements + total_withdrawals) as total_activity
FROM route_history
WHERE current_state = 'active'
    AND times_changed > 10
ORDER BY times_changed DESC, total_activity DESC
LIMIT 50;
```

### Oldest Active Routes

Find the longest-lived routes in the routing table:

```sql
SELECT
    prefix,
    router_ip,
    peer_ip,
    first_seen,
    last_updated,
    AGE(NOW(), first_seen) as route_age,
    times_changed,
    family
FROM route_history
WHERE current_state = 'active'
ORDER BY first_seen ASC
LIMIT 50;
```

### Newest Routes (Recent Announcements)

Identify recently announced routes:

```sql
SELECT
    prefix,
    router_ip,
    peer_ip,
    next_hop,
    as_path,
    first_seen,
    family
FROM route_history
WHERE current_state = 'active'
    AND first_seen >= NOW() - INTERVAL '24 hours'
ORDER BY first_seen DESC
LIMIT 100;
```

### Route Churn Over Time

Analyze route instability trends over the past week:

```sql
SELECT
    time_bucket('1 hour', time) as hour,
    COUNT(*) as total_updates,
    COUNT(DISTINCT prefix) as unique_prefixes,
    SUM(CASE WHEN is_withdrawn THEN 1 ELSE 0 END) as withdrawals,
    SUM(CASE WHEN NOT is_withdrawn THEN 1 ELSE 0 END) as announcements,
    family
FROM routes
WHERE time >= NOW() - INTERVAL '7 days'
GROUP BY hour, family
ORDER BY hour DESC;
```

## EVPN Specific Queries

### Find MAC Address in EVPN Type 2 Routes

Search for a specific MAC address across all EVPN Type 2 routes:

```sql
SELECT
    prefix,
    router_ip,
    peer_ip,
    mac_address,
    ip_address,
    route_distinguisher,
    esi,
    ethernet_tag_id,
    mpls_label1,
    mpls_label2,
    time,
    is_withdrawn
FROM routes
WHERE family = 'EVPN'
    AND route_type = 'MAC/IP Advertisement'
    AND mac_address = '00:50:56:9c:69:b6'  -- Replace with target MAC
ORDER BY time DESC;
```

### EVPN Route Types Distribution

Get an overview of EVPN route type distribution:

```sql
SELECT
    route_type,
    COUNT(*) as route_count,
    COUNT(DISTINCT router_ip) as router_count,
    COUNT(DISTINCT route_distinguisher) as rd_count
FROM routes
WHERE family = 'EVPN'
    AND is_withdrawn = false
    AND time >= NOW() - INTERVAL '24 hours'
GROUP BY route_type
ORDER BY route_count DESC;
```

### EVPN ESI (Ethernet Segment) Analysis

Analyze Ethernet Segment activity:

```sql
SELECT
    esi,
    route_distinguisher,
    COUNT(*) as route_count,
    COUNT(DISTINCT mac_address) as unique_macs,
    COUNT(DISTINCT ip_address) as unique_ips,
    MIN(time) as first_seen,
    MAX(time) as last_seen
FROM routes
WHERE family = 'EVPN'
    AND esi IS NOT NULL
    AND esi != '00:00:00:00:00:00:00:00:00:00'
    AND is_withdrawn = false
GROUP BY esi, route_distinguisher
ORDER BY route_count DESC;
```

## Router and Peer Analysis

### Active Router Sessions

Monitor currently active router sessions:

```sql
SELECT
    router_ip,
    router_name,
    session_start,
    AGE(NOW(), session_start) as session_duration,
    peer_as,
    peer_bgp_id,
    total_messages,
    status
FROM router_sessions
WHERE status = 'active'
ORDER BY session_start ASC;
```

### Peer Statistics (Last 24 Hours)

Analyze peer activity and message counts:

```sql
SELECT
    router_ip,
    peer_ip,
    peer_as,
    COUNT(*) as total_updates,
    COUNT(DISTINCT prefix) as unique_prefixes,
    SUM(CASE WHEN is_withdrawn THEN 1 ELSE 0 END) as withdrawals,
    SUM(CASE WHEN NOT is_withdrawn THEN 1 ELSE 0 END) as announcements,
    family
FROM routes
WHERE time >= NOW() - INTERVAL '24 hours'
GROUP BY router_ip, peer_ip, peer_as, family
ORDER BY total_updates DESC;
```

### Router Message Volume

Monitor message processing volume per router:

```sql
SELECT
    router_ip,
    COUNT(*) as total_messages,
    COUNT(CASE WHEN family = 'IPv4' THEN 1 END) as ipv4_messages,
    COUNT(CASE WHEN family = 'IPv6' THEN 1 END) as ipv6_messages,
    COUNT(CASE WHEN family = 'EVPN' THEN 1 END) as evpn_messages,
    MIN(time) as first_message,
    MAX(time) as last_message
FROM routes
WHERE time >= NOW() - INTERVAL '24 hours'
GROUP BY router_ip
ORDER BY total_messages DESC;
```

## AS Path Analysis

### Most Common AS Paths

Identify the most frequently seen AS paths:

```sql
SELECT
    as_path,
    COUNT(*) as occurrence_count,
    COUNT(DISTINCT prefix) as unique_prefixes,
    COUNT(DISTINCT router_ip) as router_count
FROM routes
WHERE time >= NOW() - INTERVAL '24 hours'
    AND is_withdrawn = false
    AND as_path IS NOT NULL
GROUP BY as_path
ORDER BY occurrence_count DESC
LIMIT 50;
```

### Routes by Origin AS

Analyze routes by their origin AS (last AS in path):

```sql
SELECT
    RIGHT(TRIM(as_path), POSITION(' ' IN REVERSE(TRIM(as_path) || ' ')) - 1) as origin_as,
    COUNT(*) as route_count,
    COUNT(DISTINCT prefix) as unique_prefixes
FROM routes
WHERE time >= NOW() - INTERVAL '24 hours'
    AND is_withdrawn = false
    AND as_path IS NOT NULL
    AND family = 'IPv4'
GROUP BY origin_as
ORDER BY route_count DESC
LIMIT 30;
```

## Prefix Analysis

### Largest Prefixes (Most Specific)

Find the most specific prefixes in the routing table:

```sql
SELECT
    prefix,
    prefix_len,
    router_ip,
    peer_ip,
    next_hop,
    as_path,
    time,
    family
FROM routes
WHERE is_withdrawn = false
    AND time >= NOW() - INTERVAL '24 hours'
ORDER BY prefix_len DESC, family, prefix
LIMIT 100;
```

### Prefix Length Distribution

Analyze the distribution of prefix lengths:

```sql
SELECT
    prefix_len,
    family,
    COUNT(*) as route_count,
    COUNT(DISTINCT prefix) as unique_prefixes,
    COUNT(DISTINCT router_ip) as router_count
FROM routes
WHERE is_withdrawn = false
    AND time >= NOW() - INTERVAL '24 hours'
GROUP BY prefix_len, family
ORDER BY family, prefix_len;
```

## Performance and Statistics

### Hourly Route Statistics (Pre-computed)

Use the continuous aggregate for fast hourly statistics:

```sql
SELECT
    hour,
    router_ip,
    peer_ip,
    family,
    total_updates,
    unique_prefixes,
    withdrawals,
    announcements,
    (announcements - withdrawals) as net_announcements
FROM hourly_route_stats
WHERE hour >= NOW() - INTERVAL '7 days'
ORDER BY hour DESC, total_updates DESC;
```

### Database Size and Growth

Monitor table sizes and growth:

```sql
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
    pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

## Advanced Monitoring Queries

### Route Leak Detection

Detect potential route leaks (routes with unusually long AS paths):

```sql
SELECT
    prefix,
    router_ip,
    peer_ip,
    as_path,
    array_length(string_to_array(as_path, ' '), 1) as path_length,
    time,
    family
FROM routes
WHERE is_withdrawn = false
    AND time >= NOW() - INTERVAL '24 hours'
    AND as_path IS NOT NULL
    AND array_length(string_to_array(as_path, ' '), 1) > 10  -- Adjust threshold
ORDER BY path_length DESC
LIMIT 50;
```

### Rapid Route Changes (Flapping Detection)

Identify routes that are changing very frequently (potential flapping):

```sql
SELECT
    prefix,
    router_ip,
    peer_ip,
    COUNT(*) as changes_last_hour,
    array_agg(DISTINCT is_withdrawn) as change_types,
    MIN(time) as first_change,
    MAX(time) as last_change
FROM routes
WHERE time >= NOW() - INTERVAL '1 hour'
GROUP BY prefix, router_ip, peer_ip
HAVING COUNT(*) > 5  -- More than 5 changes in an hour
ORDER BY changes_last_hour DESC;
```

### Next-hop Analysis

Analyze next-hop diversity and changes:

```sql
SELECT
    next_hop,
    COUNT(*) as route_count,
    COUNT(DISTINCT prefix) as unique_prefixes,
    COUNT(DISTINCT router_ip) as router_count,
    family
FROM routes
WHERE is_withdrawn = false
    AND time >= NOW() - INTERVAL '24 hours'
    AND next_hop IS NOT NULL
GROUP BY next_hop, family
ORDER BY route_count DESC
LIMIT 50;
```

## Query Performance Tips

!!! tip "Performance Optimization"
    - Always include time constraints in your queries to leverage TimescaleDB's time-partitioning
    - Use the `hourly_route_stats` materialized view for aggregated data analysis
    - Add appropriate indexes for frequently queried columns
    - Consider using `time_bucket()` for time-series aggregations

!!! note "Query Customization"
    - Replace time intervals (`INTERVAL '24 hours'`) with your desired timeframe
    - Adjust thresholds and limits based on your network size and requirements
    - Use specific router IPs or peer IPs to focus on particular network segments