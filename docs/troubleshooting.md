# Logging & Troubleshooting

This guide helps you monitor PyBMP operations, understand log outputs, and troubleshoot common issues.

## Log Configuration

### Log Levels

PyBMP supports multiple log levels for different verbosity:

| Level | Description | Use Case |
|-------|-------------|----------|
| `DEBUG` | Very detailed information | Development and deep debugging |
| `INFO` | General information about operation | Normal production monitoring |
| `WARNING` | Warning messages about potential issues | Production with enhanced monitoring |
| `ERROR` | Error conditions that don't stop operation | Production (default) |
| `CRITICAL` | Critical errors that may stop operation | Production alerts |

### Setting Log Level

```bash
# Environment variable
export LOG_LEVEL=DEBUG

# Docker run
docker run -e LOG_LEVEL=DEBUG ...

# Docker Compose
environment:
  LOG_LEVEL: DEBUG
```

### Log Format

PyBMP uses structured logging with the following format:

```
2024-01-15 10:30:45,123 - module_name - INFO - Message content
TIMESTAMP - LOGGER_NAME - LEVEL - MESSAGE
```

## Log Sources

### Main Application Logs

Monitor the main application container:

```bash
# Docker Compose
docker-compose logs -f bmp-collector

# Docker container
docker logs -f bmp-collector

# Follow logs with timestamps
docker-compose logs -f -t bmp-collector
```

### Database Logs

Monitor TimescaleDB operations:

```bash
# Database container logs
docker-compose logs -f timescaledb

# PostgreSQL logs inside container
docker exec -it bmp-timescaledb tail -f /var/log/postgresql/postgresql-15-main.log
```

## Understanding Log Messages

### Normal Operation Logs

#### Startup Sequence

```
2024-01-15 10:30:45 - src.main - INFO - Starting BMP Collector...
2024-01-15 10:30:45 - src.database.connection - INFO - Database connection established
2024-01-15 10:30:46 - src.bmp.server - INFO - BMP server starting on 0.0.0.0:11019
2024-01-15 10:30:46 - src.bmp.server - INFO - BMP server listening for connections
```

#### Router Connection

```
2024-01-15 10:31:20 - src.bmp.server - INFO - New connection from 192.168.1.10:51234
2024-01-15 10:31:21 - src.bmp.processor - INFO - Router 192.168.1.10 session started
2024-01-15 10:31:21 - src.bmp.processor - INFO - Processing initiation message from 192.168.1.10
```

#### Route Processing

```
2024-01-15 10:31:25 - src.bmp.processor - INFO - Processed 150 route updates from 192.168.1.10
2024-01-15 10:31:30 - src.bmp.processor - DEBUG - Route announcement: 10.0.0.0/8 via 192.168.1.1
2024-01-15 10:31:35 - src.bmp.processor - DEBUG - Route withdrawal: 172.16.0.0/12
```

### Warning Messages

#### Buffer Management

```
2024-01-15 10:35:00 - src.bmp.server - WARNING - High buffer usage for connection 192.168.1.10 (85%)
2024-01-15 10:35:30 - src.bmp.processor - WARNING - Batch processing delayed, queue size: 500
```

#### Database Performance

```
2024-01-15 10:40:00 - src.database.connection - WARNING - Database query slow: 1.5s
2024-01-15 10:40:15 - src.database.connection - WARNING - Connection pool near capacity: 18/20
```

### Error Messages

#### Connection Issues

```
2024-01-15 10:45:00 - src.bmp.server - ERROR - Connection lost from 192.168.1.10: [Errno 104] Connection reset by peer
2024-01-15 10:45:10 - src.database.connection - ERROR - Database connection failed: connection timeout
```

#### Data Processing Errors

```
2024-01-15 10:50:00 - src.bmp.parser - ERROR - Invalid BMP message format from 192.168.1.10
2024-01-15 10:50:05 - src.bmp.bgp_parser - ERROR - Malformed BGP update in BMP message
```

## Monitoring with Prometheus Metrics

### Key Metrics to Monitor

Access metrics at `http://localhost:9090/metrics`:

#### Connection Metrics

```
# Active connections
bmp_active_connections{router_ip="192.168.1.10"} 1

# Total messages received
bmp_messages_received_total{router_ip="192.168.1.10",message_type="route_monitoring"} 1500

# Message processing rate
bmp_message_processing_rate{router_ip="192.168.1.10"} 25.5
```

#### Database Metrics

```
# Database queries executed
database_queries_total{operation="insert"} 5000

# Database connection pool usage
database_pool_connections{state="active"} 8
database_pool_connections{state="idle"} 12

# Query execution time
database_query_duration_seconds{operation="insert",quantile="0.95"} 0.05
```

#### System Metrics

```
# Memory usage
process_resident_memory_bytes 256000000

# CPU usage
process_cpu_seconds_total 120.5

# File descriptors
process_open_fds 45
```

### Setting Up Alerts

Example Prometheus alerting rules:

```yaml
groups:
  - name: pybmp_alerts
    rules:
      - alert: BMPHighConnectionLoss
        expr: rate(bmp_connections_lost_total[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High BMP connection loss rate"
          description: "BMP connection loss rate is {{ $value }} connections/sec"

      - alert: BMPDatabaseSlow
        expr: database_query_duration_seconds{quantile="0.95"} > 1.0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Database queries are slow"
          description: "95th percentile query time is {{ $value }} seconds"

      - alert: BMPHighMemoryUsage
        expr: process_resident_memory_bytes > 1000000000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "PyBMP using {{ $value | humanize1024 }}B of memory"
```

## Common Issues and Solutions

### 1. Router Connection Issues

#### Symptoms
```
ERROR - Connection lost from 192.168.1.10: [Errno 104] Connection reset by peer
WARNING - No data received from 192.168.1.10 for 60 seconds
```

#### Possible Causes & Solutions

**Network Connectivity:**
```bash
# Test connectivity from PyBMP host to router
telnet 192.168.1.10 179  # BGP port should be open
ping 192.168.1.10

# Check firewall rules
iptables -L -n | grep 11019
ufw status
```

**Router Configuration:**
```bash
# Verify router BMP configuration
# Check if router can reach PyBMP
show ip route <PYBMP-IP>
show bmp summary
```

**PyBMP Configuration:**
```bash
# Check if PyBMP is listening on correct interface
netstat -tulpn | grep 11019
ss -tulpn | grep 11019

# Verify container networking (if using Docker)
docker port bmp-collector
```

### 2. Database Performance Issues

#### Symptoms
```
WARNING - Database query slow: 2.5s
ERROR - Database connection timeout
WARNING - Connection pool near capacity: 20/20
```

#### Solutions

**Optimize Database:**
```sql
-- Update table statistics
ANALYZE routes;
ANALYZE route_history;

-- Check for missing indexes
SELECT schemaname, tablename, attname, n_distinct, correlation
FROM pg_stats
WHERE schemaname = 'public' AND tablename = 'routes';

-- Add custom indexes for frequent queries
CREATE INDEX CONCURRENTLY idx_routes_recent_by_router
ON routes(router_ip, time DESC)
WHERE time > NOW() - INTERVAL '7 days';
```

**Tune Database Configuration:**
```postgresql
-- postgresql.conf
max_connections = 200
shared_buffers = 2GB
work_mem = 8MB
effective_cache_size = 8GB
checkpoint_timeout = 10min
wal_buffers = 16MB
```

**Adjust Connection Pool:**
```env
# Increase database pool size
DB_POOL_SIZE=30
DB_MAX_OVERFLOW=60

# Adjust batch processing
BATCH_SIZE=500
BATCH_TIMEOUT_SECONDS=10
```

### 3. High Memory Usage

#### Symptoms
```
WARNING - High memory usage detected: 1.2GB
ERROR - Out of memory: cannot allocate more connections
```

#### Solutions

**Monitor Memory Usage:**
```bash
# Container memory usage
docker stats bmp-collector

# Detailed memory breakdown
docker exec bmp-collector cat /proc/meminfo
docker exec bmp-collector ps aux --sort=-%mem
```

**Optimize Configuration:**
```env
# Reduce buffer sizes
BMP_BUFFER_SIZE=32768
BMP_MAX_CONNECTIONS=50

# Limit batch sizes
BATCH_SIZE=500
WORKER_THREADS=2
```

**Database Memory:**
```sql
-- Check database cache hit ratio
SELECT datname,
       blks_read,
       blks_hit,
       round((blks_hit::float/(blks_read+blks_hit+1)*100)::numeric, 2) as cache_hit_ratio
FROM pg_stat_database
WHERE datname = 'bmp_collector';
```

### 4. Message Processing Delays

#### Symptoms
```
WARNING - Batch processing delayed, queue size: 1000
INFO - Processing lag: 30 seconds behind real-time
```

#### Solutions

**Increase Processing Capacity:**
```env
# More worker threads
WORKER_THREADS=8

# Larger batch sizes (if database can handle)
BATCH_SIZE=2000

# Shorter timeout for faster processing
BATCH_TIMEOUT_SECONDS=2
```

**Database Optimization:**
```sql
-- Partition old data
SELECT drop_chunks('routes', INTERVAL '30 days');

-- Update chunk interval for better performance
SELECT set_chunk_time_interval('routes', INTERVAL '6 hours');
```

### 5. Log File Issues

#### Log Rotation

```bash
# Setup logrotate for Docker logs
cat > /etc/logrotate.d/docker-pybmp << EOF
/var/lib/docker/containers/*/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        docker kill --signal=USR1 $(docker ps -q)
    endscript
}
EOF
```

#### Disk Space Monitoring

```bash
# Monitor log directory size
du -sh /var/lib/docker/containers/*/

# Clean old logs
docker system prune -f
docker container prune -f
```

## Debugging Tools

### Enable Debug Logging

```bash
# Temporarily enable debug logging
docker exec bmp-collector kill -USR1 1

# Or restart with debug logging
docker-compose down
docker-compose up -d -e LOG_LEVEL=DEBUG
```

### Database Query Analysis

```sql
-- Show slow queries
SELECT query, mean_time, calls, total_time
FROM pg_stat_statements
WHERE mean_time > 100
ORDER BY mean_time DESC;

-- Show current running queries
SELECT pid, now() - pg_stat_activity.query_start AS duration, query
FROM pg_stat_activity
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes';
```

### Network Packet Capture

```bash
# Capture BMP traffic for analysis
tcpdump -i any -w bmp_capture.pcap port 11019

# Analyze with tshark
tshark -r bmp_capture.pcap -Y "tcp.port == 11019"
```

### Resource Monitoring

```bash
# Real-time monitoring
watch -n 1 'docker stats --no-stream bmp-collector'

# Continuous monitoring with timestamps
while true; do
    echo "$(date): $(docker stats --no-stream --format 'table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}' bmp-collector)"
    sleep 60
done
```

## Performance Tuning

### Application Tuning

```env
# Optimize for high-volume environments
BMP_BUFFER_SIZE=131072
BMP_MAX_CONNECTIONS=200
BATCH_SIZE=5000
BATCH_TIMEOUT_SECONDS=1
WORKER_THREADS=16
```

### Database Tuning

```sql
-- Optimize for time-series workload
SET maintenance_work_mem = '1GB';
SET checkpoint_timeout = '15min';
SET wal_compression = on;
SET log_min_duration_statement = 1000;
```

### Container Resource Limits

```yaml
# docker-compose.yml
services:
  bmp-collector:
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2.0'
        reservations:
          memory: 1G
          cpus: '1.0'
```

## Getting Help

When reporting issues, include:

1. **Log snippets** with timestamps
2. **Configuration** (sanitized)
3. **System information** (OS, Docker version, hardware)
4. **Network topology** and router models
5. **Metrics data** if available

```bash
# Generate diagnostic report
docker-compose logs --tail=100 > pybmp-logs.txt
docker stats --no-stream > pybmp-stats.txt
curl -s http://localhost:9090/metrics > pybmp-metrics.txt
```