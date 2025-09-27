# Installation & Configuration

This guide walks you through installing and configuring PyBMP for various deployment scenarios.

## Prerequisites

- Docker and Docker Compose (recommended)
- Python 3.11+ (for manual installation)
- PostgreSQL 15+ with TimescaleDB extension (for external database)
- Network access on port 11019 for BMP traffic

## Installation Methods

### Method 1: Docker Compose (Recommended)

The easiest way to get started with PyBMP including TimescaleDB and optional Grafana dashboard.

#### Step 1: Clone the Repository

```bash
git clone https://github.com/DigitalVortexLLC/pybmp.git
cd pybmp
```

#### Step 2: Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit the configuration (IMPORTANT: Set a strong DB password)
nano .env
```

**Critical Configuration:**
```env
# Database Configuration
DB_PASSWORD=your_very_strong_password_here

# BMP Server Configuration
BMP_LISTEN_PORT=11019  # Default BMP port

# Data Retention
DATA_RETENTION_DAYS=90

# Logging
LOG_LEVEL=INFO
```

#### Step 3: Start Services

```bash
# Start all services (PyBMP, TimescaleDB, Grafana)
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f bmp-collector
```

#### Step 4: Verify Installation

```bash
# Check if BMP server is listening
netstat -tulpn | grep 11019

# Check database connectivity
docker exec -it bmp-timescaledb psql -U bmp_user -d bmp_collector -c "SELECT version();"

# Check Prometheus metrics
curl http://localhost:9090/metrics
```

### Method 2: Pre-built Docker Image

Use the pre-built image from GitHub Container Registry with your existing PostgreSQL database.

#### Pull the Image

```bash
docker pull ghcr.io/digitalvortexllc/pybmp:latest
```

#### Run with External Database

```bash
docker run -d \
  --name bmp-collector \
  -p 11019:11019 \
  -p 9090:9090 \
  -e DB_HOST=your-postgres-host \
  -e DB_PORT=5432 \
  -e DB_NAME=bmp_collector \
  -e DB_USER=bmp_user \
  -e DB_PASSWORD=your-secure-password \
  -e BMP_LISTEN_HOST=0.0.0.0 \
  -e BMP_LISTEN_PORT=11019 \
  -e LOG_LEVEL=INFO \
  -v /path/to/logs:/app/logs \
  ghcr.io/digitalvortexllc/pybmp:latest
```

### Method 3: Manual Installation

For development or custom deployment scenarios.

#### Step 1: Install Dependencies

```bash
# Install Poetry (if not already installed)
curl -sSL https://install.python-poetry.org | python3 -

# Install project dependencies
poetry install

# Or using pip
pip install -r requirements.txt
```

#### Step 2: Database Setup

```bash
# Create database and user
createdb -h localhost -U postgres bmp_collector
createuser -h localhost -U postgres bmp_user

# Install TimescaleDB extension and schema
psql -h localhost -U postgres -d bmp_collector -f schema.sql
```

#### Step 3: Configuration

```bash
# Create environment file
cp .env.example .env

# Edit configuration
nano .env
```

#### Step 4: Run the Application

```bash
# Using Poetry
poetry run python main.py

# Or directly
python main.py
```

## Configuration Options

### Environment Variables

| Variable | Default | Description | Required |
|----------|---------|-------------|----------|
| `DB_HOST` | localhost | Database host | ✓ |
| `DB_PORT` | 5432 | Database port | ✓ |
| `DB_NAME` | bmp_collector | Database name | ✓ |
| `DB_USER` | bmp_user | Database user | ✓ |
| `DB_PASSWORD` | - | Database password | ✓ |
| `BMP_LISTEN_HOST` | 0.0.0.0 | BMP server bind address | - |
| `BMP_LISTEN_PORT` | 11019 | BMP server port | - |
| `DATA_RETENTION_DAYS` | 90 | Data retention period | - |
| `LOG_LEVEL` | INFO | Log level (DEBUG, INFO, WARNING, ERROR) | - |
| `METRICS_PORT` | 9090 | Prometheus metrics port | - |
| `BMP_BUFFER_SIZE` | 65536 | Buffer size for BMP connections | - |
| `BMP_MAX_CONNECTIONS` | 100 | Maximum concurrent connections | - |

### Custom Port Configuration

To run PyBMP on a custom port:

```bash
# Method 1: Environment variable
export BMP_LISTEN_PORT=12345

# Method 2: Docker
docker run -p 12345:12345 -e BMP_LISTEN_PORT=12345 ...

# Method 3: Docker Compose
# Edit docker-compose.yml:
ports:
  - "12345:12345"
environment:
  BMP_LISTEN_PORT: 12345
```

### External PostgreSQL Database

#### Database Requirements

- PostgreSQL 15+ with TimescaleDB extension
- Minimum configuration:
  ```sql
  -- postgresql.conf
  max_connections = 200
  shared_preload_libraries = 'timescaledb'

  -- Memory settings (adjust based on available RAM)
  shared_buffers = 1GB
  work_mem = 4MB
  ```

#### Setup Steps

1. **Install TimescaleDB Extension:**
   ```sql
   CREATE EXTENSION IF NOT EXISTS timescaledb;
   ```

2. **Create Database and User:**
   ```sql
   CREATE DATABASE bmp_collector;
   CREATE USER bmp_user WITH PASSWORD 'strong_password';
   GRANT ALL PRIVILEGES ON DATABASE bmp_collector TO bmp_user;
   ```

3. **Load Schema:**
   ```bash
   psql -h your-db-host -U bmp_user -d bmp_collector -f schema.sql
   ```

4. **Configure PyBMP:**
   ```env
   DB_HOST=your-db-host
   DB_PORT=5432
   DB_NAME=bmp_collector
   DB_USER=bmp_user
   DB_PASSWORD=strong_password
   ```

### Performance Tuning

#### Database Optimization

```sql
-- Adjust chunk interval for time partitioning (default: 7 days)
SELECT set_chunk_time_interval('routes', INTERVAL '1 day');

-- Add additional indexes for specific query patterns
CREATE INDEX idx_routes_custom ON routes(router_ip, family) WHERE time > NOW() - INTERVAL '7 days';

-- Update statistics for query optimization
ANALYZE routes;
ANALYZE route_history;
```

#### Application Tuning

```env
# Increase buffer sizes for high-volume environments
BMP_BUFFER_SIZE=131072

# Adjust connection limits
BMP_MAX_CONNECTIONS=200

# Batch processing settings
BATCH_SIZE=2000
BATCH_TIMEOUT_SECONDS=3
WORKER_THREADS=8
```

## Router Configuration

Configure your routers to send BMP data to PyBMP:

### Cisco IOS-XR

```
router bgp <AS-NUMBER>
 bmp server 1
  host <PYBMP-IP> port 11019
  description "PyBMP Collector"
  update-source <interface>
  flapping-delay 60
  initial-delay 5
  stats-reporting-period 60
  route-monitoring pre-policy
 !
!
```

### Juniper JunOS

```
routing-options {
    bmp {
        station pybmp-collector {
            connection-mode active;
            station-address <PYBMP-IP>;
            station-port 11019;
            routing-instance-id default;
            local-address <ROUTER-IP>;
            monitor enable;
            route-monitoring {
                none;
                pre-policy;
            }
        }
    }
}
```

### Arista EOS

```
router bgp <AS-NUMBER>
 bmp server <PYBMP-IP> port 11019
 bmp ribs pre-policy
!
```

## Network Security

### Firewall Configuration

Allow BMP traffic from your routers:

```bash
# iptables example
iptables -A INPUT -p tcp --dport 11019 -s <ROUTER-NETWORK>/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 9090 -s <MONITORING-NETWORK>/24 -j ACCEPT

# ufw example
ufw allow from <ROUTER-IP> to any port 11019
ufw allow from <MONITORING-IP> to any port 9090
```

### TLS/SSL Considerations

For production deployments, consider:

- Running PyBMP behind a TLS-terminating proxy
- Using VPN or dedicated network connections
- Implementing network segmentation

## Monitoring Setup

### Prometheus Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'pybmp'
    static_configs:
      - targets: ['<PYBMP-HOST>:9090']
    scrape_interval: 30s
    metrics_path: '/metrics'
```

### Grafana Dashboard

1. **Add TimescaleDB Data Source:**
   - URL: `postgresql://bmp_user:password@timescaledb:5432/bmp_collector`
   - SSL Mode: disable (for local deployments)

2. **Import Dashboard:**
   - Use the included Grafana dashboard configuration
   - Customize panels based on your monitoring needs

## Health Checks

Monitor PyBMP health:

```bash
# Container health check
docker exec bmp-collector python -c "import src.bmp.server; print('OK')"

# Database connectivity
docker exec bmp-collector python -c "
from src.database.connection import DatabasePool
from src.utils.config import get_settings
import asyncio

async def test():
    settings = get_settings()
    pool = DatabasePool(settings)
    await pool.connect()
    print('Database: OK')
    await pool.disconnect()

asyncio.run(test())
"

# Metrics endpoint
curl -f http://localhost:9090/metrics > /dev/null && echo "Metrics: OK"
```

## Troubleshooting Installation

### Common Issues

1. **Port Already in Use:**
   ```bash
   # Find process using port 11019
   lsof -i :11019
   # Kill process or change port
   ```

2. **Database Connection Failed:**
   ```bash
   # Test database connectivity
   docker exec -it bmp-timescaledb psql -U bmp_user -d bmp_collector
   ```

3. **Permission Denied:**
   ```bash
   # Fix log directory permissions
   mkdir -p logs
   chmod 755 logs
   ```

4. **Memory Issues:**
   ```bash
   # Check available memory
   free -h
   # Adjust Docker memory limits or database settings
   ```

For more troubleshooting information, see the [Logging & Troubleshooting](troubleshooting.md) section.