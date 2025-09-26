# BMP Collector with TimescaleDB

A Python-based BGP Monitoring Protocol (BMP) collector that listens for BMP traffic from routers and stores route information in TimescaleDB.

## ⚠️ SECURITY NOTICE

**CRITICAL**: This application contains network-facing components. Before production deployment:

1. **Set strong database passwords** - Do not use default credentials
2. **Configure network security** - Use firewalls, VPNs, or network segmentation
3. **Review SECURITY.md** - Follow the complete security checklist
4. **Update dependencies** - Ensure all packages are current and secure

See [SECURITY.md](SECURITY.md) for complete security guidelines.

## Features

- **BMP Protocol Support**: Full BMP v3 implementation with security protections
- **Multi-Router Support**: Handle connections from multiple routers simultaneously
- **BGP Family Support**: IPv4, IPv6, and EVPN routes
- **TimescaleDB Storage**: Efficient time-series storage with automatic data retention
- **Route Tracking**: Track route history, changes, and withdrawals
- **Session Management**: Monitor router sessions and statistics
- **Security Features**: Buffer limits, input validation, rate limiting
- **Docker Ready**: Complete Docker and Docker Compose setup

## Quick Start

### Using Pre-built Docker Images (Fastest)

Pull and run the latest image directly from GitHub Container Registry:

```bash
# Pull the latest image
docker pull ghcr.io/digitalvortexllc/pybmp:latest

# Run with external PostgreSQL
docker run -d \
  --name bmp-collector \
  -p 11019:11019 \
  -p 9090:9090 \
  -e DB_HOST=your-postgres-host \
  -e DB_PASSWORD=your-secure-password \
  ghcr.io/digitalvortexllc/pybmp:latest
```

For detailed Docker usage, see [DOCKER.md](DOCKER.md).

### Using Docker Compose (Recommended for Development)

1. Clone the repository
2. **IMPORTANT**: Set secure passwords:
   ```bash
   cp .env.example .env
   # Edit .env and set DB_PASSWORD to a strong password
   nano .env
   ```
3. Start the services:
   ```bash
   docker-compose up -d
   ```

The BMP collector will be listening on port 11019 for router connections.

## Configuration

**CRITICAL** environment variables marked below:

| Variable | Default | Description | Security Level |
|----------|---------|-------------|----------------|
| `DB_PASSWORD` | **REQUIRED** | Database password | **CRITICAL** |
| `BMP_LISTEN_HOST` | 0.0.0.0 | BMP server listen address | High |
| `BMP_LISTEN_PORT` | 11019 | BMP server port | Medium |
| `DATA_RETENTION_DAYS` | 90 | Days to retain route data | Low |

## Security Features

### Built-in Protections
- **Buffer overflow protection**: 10MB per connection limit
- **Message size validation**: 1MB maximum message size
- **Connection limits**: Configurable max connections per IP
- **Input validation**: Comprehensive BGP data validation
- **SQL injection prevention**: Parameterized queries only
- **Rate limiting**: Token bucket algorithm for message throttling

For complete security information, see [SECURITY.md](SECURITY.md).

## License

MIT License