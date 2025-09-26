# Docker Usage Guide

This document explains how to use the pre-built Docker images for the BMP Collector.

## Quick Start

### Pull the Latest Image

```bash
docker pull ghcr.io/digitalvortexllc/pybmp:latest
```

### Run with Default Configuration

```bash
docker run -d \
  --name bmp-collector \
  -p 11019:11019 \
  -p 9090:9090 \
  ghcr.io/digitalvortexllc/pybmp:latest
```

### Run with Custom Configuration

```bash
docker run -d \
  --name bmp-collector \
  -p 11019:11019 \
  -p 9090:9090 \
  -e DB_HOST=your-postgres-host \
  -e DB_PORT=5432 \
  -e DB_NAME=bmp_collector \
  -e DB_USER=bmp_user \
  -e DB_PASSWORD=your-password \
  -e LOG_LEVEL=DEBUG \
  ghcr.io/digitalvortexllc/pybmp:latest
```

### Run with Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: bmp_collector
      POSTGRES_USER: bmp_user
      POSTGRES_PASSWORD: bmp_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  bmp-collector:
    image: ghcr.io/digitalvortexllc/pybmp:latest
    depends_on:
      - postgres
    environment:
      DB_HOST: postgres
      DB_PORT: 5432
      DB_NAME: bmp_collector
      DB_USER: bmp_user
      DB_PASSWORD: bmp_password
      LOG_LEVEL: INFO
    ports:
      - "11019:11019"  # BMP server port
      - "9090:9090"    # Metrics port
    volumes:
      - ./config:/app/config:ro
      - bmp_logs:/app/logs

volumes:
  postgres_data:
  bmp_logs:
```

Then run:

```bash
docker-compose up -d
```

## Available Tags

- `latest` - Latest stable release from the main branch
- `develop` - Latest development build
- `v1.0.0` - Specific version tags
- `main-<sha>` - Builds from specific commits

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `bmp_collector` | Database name |
| `DB_USER` | `bmp_user` | Database user |
| `DB_PASSWORD` | - | Database password (required) |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `BMP_PORT` | `11019` | BMP server listening port |
| `METRICS_PORT` | `9090` | Prometheus metrics port |

## Ports

- `11019` - BMP server (receives BMP messages from routers)
- `9090` - Metrics endpoint (Prometheus scraping)

## Volumes

- `/app/logs` - Application logs
- `/app/data` - Application data
- `/app/config` - Configuration files (optional)

## Health Check

The container includes a health check that verifies the application can start properly. You can check the health status with:

```bash
docker ps
# Look for the health status in the STATUS column
```

## Multi-Architecture Support

The images are built for both:
- `linux/amd64` (Intel/AMD x86_64)
- `linux/arm64` (ARM64/Apple Silicon)

Docker will automatically pull the correct architecture for your platform.

## Example: Connecting Routers

Configure your routers to send BMP messages to the collector:

### Cisco IOS-XR Example

```
router bgp 65001
 bmp server 1
  host <collector-ip> port 11019
  description "BMP Collector"
  initial-delay 5
  stats-reporting-period 60
  update-source Loopback0
 !
 neighbor-group INTERNAL
  bmp-activate server 1
 !
```

### Juniper Junos Example

```
routing-options {
    bmp {
        station collector {
            address <collector-ip>;
            port 11019;
            connection-mode active;
            statistics-timeout 60;
        }
    }
}

protocols {
    bgp {
        bmp {
            monitor enable;
            station collector;
        }
    }
}
```

## Monitoring and Metrics

The collector exposes Prometheus metrics on port 9090. You can view metrics at:

```
http://localhost:9090/metrics
```

Common metrics include:
- `bmp_messages_total` - Total BMP messages received
- `bmp_routes_total` - Total routes processed
- `bmp_peers_active` - Number of active BGP peers
- `evpn_routes_by_type` - EVPN routes by type (1-5)

## Troubleshooting

### Check Container Logs

```bash
docker logs bmp-collector
```

### Debug Mode

```bash
docker run -e LOG_LEVEL=DEBUG ghcr.io/digitalvortexllc/pybmp:latest
```

### Database Connection Issues

Ensure your PostgreSQL database is accessible and the credentials are correct:

```bash
# Test database connection
docker run --rm -it postgres:15 psql \
  "postgresql://bmp_user:bmp_password@your-host:5432/bmp_collector"
```

## Building Locally

If you prefer to build the image locally:

```bash
git clone https://github.com/DigitalVortexLLC/pybmp.git
cd pybmp
docker build -t pybmp:local .
```

## Security

- The container runs as a non-root user (`appuser`)
- Only necessary ports are exposed
- Uses distroless base images for minimal attack surface
- Regular security scanning via GitHub Actions

For production deployments, consider:
- Using secrets management for database credentials
- Running behind a reverse proxy
- Implementing network policies
- Regular image updates