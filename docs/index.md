# PyBMP - BGP Monitoring Protocol Collector

Welcome to PyBMP, a high-performance Python-based BGP Monitoring Protocol (BMP) collector that provides real-time BGP route monitoring and historical analysis capabilities.

## Overview

PyBMP is designed to collect, store, and analyze BGP routing information from network routers using the BMP protocol. It provides network operators with deep insights into BGP routing behavior, route changes, and network topology evolution over time.

## Key Features

### 🚀 **Protocol Support**
- **Full BMP v3 Implementation** - Complete support for BGP Monitoring Protocol version 3
- **Multi-Router Support** - Handle connections from multiple routers simultaneously
- **BGP Family Support** - IPv4 unicast, IPv6 unicast, and EVPN routes
- **Real-time Processing** - Process and store routing updates as they arrive

### 🗄️ **Data Storage & Analytics**
- **TimescaleDB Integration** - Efficient time-series storage optimized for routing data
- **Route History Tracking** - Track route announcements, withdrawals, and changes over time
- **Automated Data Retention** - Configurable retention policies (default: 90 days)
- **Continuous Aggregates** - Pre-computed hourly statistics for fast querying

### 📊 **Monitoring & Observability**
- **Session Management** - Monitor router sessions and connection status
- **Prometheus Metrics** - Built-in metrics endpoint for monitoring and alerting
- **Structured Logging** - Comprehensive logging with configurable levels
- **Health Checks** - Container health monitoring and status reporting

### 🔒 **Security Features**
- **Buffer Overflow Protection** - 10MB per connection limit
- **Message Size Validation** - 1MB maximum message size limit
- **Connection Limits** - Configurable maximum connections per IP
- **Input Validation** - Comprehensive BGP data validation
- **SQL Injection Prevention** - Parameterized queries only
- **Rate Limiting** - Token bucket algorithm for message throttling

### 🐳 **Deployment Ready**
- **Docker Support** - Complete Docker and Docker Compose setup
- **Container Registry** - Pre-built images available on GitHub Container Registry
- **Environment Configuration** - Flexible configuration via environment variables
- **Health Monitoring** - Built-in health check endpoints

## Architecture

PyBMP follows a modern, scalable architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   BGP Routers   │────│   PyBMP Server  │────│   TimescaleDB   │
│                 │BMP │                 │    │                 │
│ Router 1, 2, 3  │    │ - Message Parse │    │ - Route Storage │
│                 │    │ - Validation    │    │ - Time-series   │
│                 │    │ - Rate Limiting │    │ - Aggregates    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              │
                       ┌─────────────────┐
                       │   Prometheus    │
                       │    Metrics      │
                       └─────────────────┘
```

## Supported Route Types

### IPv4 & IPv6 Unicast
- Standard BGP routing table entries
- Next-hop information
- AS path analysis
- Community tracking

### EVPN (Ethernet VPN)
- **Type 1**: Ethernet Auto-Discovery (AD) routes
- **Type 2**: MAC/IP Advertisement routes
- **Type 3**: Inclusive Multicast Ethernet Tag routes
- **Type 4**: Ethernet Segment routes
- **Type 5**: IP Prefix routes

Each EVPN route includes:
- Route Distinguisher (RD)
- Ethernet Segment Identifier (ESI)
- Ethernet Tag ID
- MAC addresses
- MPLS labels

## Data Model

PyBMP stores comprehensive routing information including:

- **Route Information**: Prefix, next-hop, AS path, communities
- **Temporal Data**: Announcement/withdrawal timestamps, route lifetime
- **Router Context**: Source router, peer information, session details
- **EVPN Specifics**: ESI, MAC addresses, MPLS labels, route types
- **Metadata**: Raw BMP messages, processing timestamps

## Use Cases

### Network Operations
- **Route Leak Detection** - Identify unauthorized route announcements
- **Convergence Analysis** - Measure BGP convergence times
- **Topology Discovery** - Map network topology changes over time
- **Capacity Planning** - Analyze routing table growth trends

### Security Monitoring
- **Hijack Detection** - Detect route hijacking attempts
- **Anomaly Analysis** - Identify unusual routing patterns
- **Compliance Monitoring** - Ensure routing policies are followed

### Performance Analysis
- **Route Churn Analysis** - Identify unstable routes
- **Path Analysis** - Study AS path changes over time
- **Load Distribution** - Monitor traffic distribution patterns

## Getting Started

Ready to start monitoring your BGP infrastructure? Check out our [Installation & Configuration](installation.md) guide to get PyBMP up and running in your environment.

For specific monitoring use cases, see our [Useful Queries](queries.md) section for ready-to-use SQL queries.

!!! warning "Security Notice"
    PyBMP is a network-facing application. Always review our security guidelines and ensure proper network security measures are in place before production deployment.