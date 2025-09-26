# BMP Collector Test Suite

This directory contains a comprehensive test suite for the BMP collector application, covering unit tests, integration tests, security tests, and end-to-end scenarios.

## Test Structure

```
tests/
├── conftest.py                 # Shared pytest configuration and fixtures
├── fixtures/                   # Test data and mock fixtures
│   ├── bmp_messages.py         # BMP message builders and test data
│   └── database_fixtures.py    # Database mock data and generators
├── unit/                       # Unit tests for individual components
│   ├── test_bmp_parser.py      # BMP message parser tests
│   ├── test_route_processor.py # Route processing logic tests
│   ├── test_database_connection.py # Database layer tests
│   ├── test_config.py          # Configuration management tests
│   ├── test_validation.py      # Input validation tests
│   └── test_rate_limiter.py    # Rate limiting tests
├── integration/                # Integration tests
│   ├── test_bmp_server.py      # BMP server integration tests
│   ├── test_database_operations.py # Database integration tests
│   └── test_end_to_end.py      # End-to-end message processing
└── security/                   # Security tests
    └── test_security.py        # Security vulnerability tests
```

## Test Categories

### Unit Tests (`tests/unit/`)

Unit tests focus on testing individual components in isolation with mocked dependencies:

- **BMP Parser** (`test_bmp_parser.py`): Tests message parsing, validation, and error handling
- **Route Processor** (`test_route_processor.py`): Tests route processing logic and database operations
- **Database Connection** (`test_database_connection.py`): Tests database pool management and query execution
- **Configuration** (`test_config.py`): Tests configuration loading and validation
- **Validation** (`test_validation.py`): Tests input validation and sanitization
- **Rate Limiter** (`test_rate_limiter.py`): Tests connection and message rate limiting

### Integration Tests (`tests/integration/`)

Integration tests verify component interactions and realistic workflows:

- **BMP Server** (`test_bmp_server.py`): Tests complete BMP session handling
- **Database Operations** (`test_database_operations.py`): Tests database operations with real connections
- **End-to-End** (`test_end_to_end.py`): Tests complete message processing workflows

### Security Tests (`tests/security/`)

Security tests focus on vulnerability detection and attack prevention:

- **Buffer Overflow Protection**: Tests against memory exhaustion attacks
- **SQL Injection Prevention**: Tests parameterized queries and input sanitization
- **Input Validation**: Tests malformed input handling
- **Rate Limiting**: Tests DoS protection mechanisms
- **Authentication Bypass**: Tests unauthorized access attempts

## Running Tests

### Using pytest directly

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/ -m unit
pytest tests/integration/ -m integration
pytest tests/security/ -m security

# Run with coverage
pytest --cov=src --cov-report=html --cov-report=term-missing

# Run specific test files
pytest tests/unit/test_bmp_parser.py -v

# Run tests matching pattern
pytest -k "test_parse" -v
```

### Using the test runner script

```bash
# Run all tests (default)
python run_tests.py

# Run specific test suites
python run_tests.py --mode unit
python run_tests.py --mode integration
python run_tests.py --mode security
python run_tests.py --mode performance

# Run code quality checks
python run_tests.py --mode quality

# Run security linting
python run_tests.py --mode security-lint

# Run tests in parallel
python run_tests.py --mode parallel --parallel 8

# Quick test run (skip slow tests)
python run_tests.py --fast

# Clean test artifacts
python run_tests.py --mode clean
```

## Test Configuration

### Pytest Configuration (`pytest.ini`)

The test suite is configured with:
- **Coverage**: Minimum 80% coverage requirement
- **Markers**: Unit, integration, security, slow, database markers
- **Output**: JUnit XML, HTML reports, and coverage reports
- **Async**: Automatic async test detection

### Environment Variables

Tests use the following environment variables:

```bash
DB_HOST=localhost
DB_PORT=5432
DB_NAME=test_bmp
DB_USER=test_user
DB_PASSWORD=test_password
LOG_LEVEL=DEBUG
```

### Test Database Setup

For integration tests that require a real database:

```bash
# Using Docker
docker run --name test-timescaledb \
  -e POSTGRES_PASSWORD=test_password \
  -e POSTGRES_USER=test_user \
  -e POSTGRES_DB=test_bmp \
  -p 5432:5432 \
  -d timescale/timescaledb:latest-pg15

# Apply schema
PGPASSWORD=test_password psql -h localhost -U test_user -d test_bmp -f schema.sql
```

## Test Fixtures and Utilities

### BMP Message Fixtures (`tests/fixtures/bmp_messages.py`)

Provides builders for creating valid BMP messages:

```python
from tests.fixtures.bmp_messages import BMPMessageBuilder, TEST_MESSAGES

# Use pre-built messages
route_msg = TEST_MESSAGES['route_monitoring']

# Build custom messages
custom_msg = BMPMessageBuilder.create_route_monitoring_message(
    peer_ip="192.0.2.1",
    peer_as=65001,
    nlri=['10.0.1.0/24', '10.0.2.0/24']
)
```

### Database Fixtures (`tests/fixtures/database_fixtures.py`)

Provides mock data generators:

```python
from tests.fixtures.database_fixtures import generate_mock_route_data

# Generate test routes
routes = generate_mock_route_data(count=100)
```

### Shared Fixtures (`tests/conftest.py`)

Common fixtures available to all tests:

- `test_settings`: Test configuration
- `mock_db_pool`: Mocked database pool
- `bmp_parser`: BMP parser instance
- `route_processor`: Route processor with mocked database
- Sample message fixtures for each BMP message type

## Test Markers

Tests are organized using pytest markers:

- `@pytest.mark.unit`: Unit tests
- `@pytest.mark.integration`: Integration tests
- `@pytest.mark.security`: Security tests
- `@pytest.mark.slow`: Long-running tests
- `@pytest.mark.database`: Tests requiring database
- `@pytest.mark.network`: Tests requiring network access

## Continuous Integration

The test suite integrates with GitHub Actions for:

### Main CI Pipeline (`.github/workflows/ci.yml`)
- Code quality checks (Black, isort, flake8, mypy)
- Unit tests across Python versions
- Integration tests with real database
- Security tests
- Docker build and security scanning
- Coverage reporting to Codecov

### Security Scanning (`.github/workflows/security-scan.yml`)
- Daily vulnerability scans
- Bandit security linting
- Safety dependency checking
- CodeQL analysis
- Container security scanning
- Secret detection

### Test Matrix (`.github/workflows/test-matrix.yml`)
- Cross-platform testing (Ubuntu, Windows, macOS)
- Multiple Python versions (3.11, 3.12)
- Different dependency versions
- Stress testing
- Memory profiling

## Coverage Requirements

- **Unit Tests**: Minimum 80% coverage
- **Integration Tests**: Focus on workflow coverage
- **Security Tests**: Focus on vulnerability coverage
- **Overall**: Minimum 80% combined coverage

## Performance Testing

Performance tests use pytest-benchmark:

```python
def test_message_parsing_performance(benchmark, bmp_parser):
    result = benchmark(bmp_parser.parse_message, large_message)
    assert result is not None
```

## Security Testing Best Practices

Security tests follow these principles:

1. **Input Validation**: Test all input boundaries and malformed data
2. **SQL Injection**: Verify parameterized queries prevent injection
3. **Buffer Overflow**: Test memory limits and large data handling
4. **Rate Limiting**: Verify DoS protection mechanisms
5. **Authentication**: Test access controls and authorization

## Memory Testing

Memory tests use pytest-memray for profiling:

```bash
pytest --memray tests/unit/test_bmp_parser.py
```

## Debugging Tests

### Running Tests with Debug Output

```bash
# Increase verbosity
pytest -vvv --tb=long

# Show print statements
pytest -s

# Run specific test with debugging
pytest tests/unit/test_bmp_parser.py::test_specific_function -vvs --pdb
```

### Test Data Generation

For debugging complex scenarios, use the fixture generators:

```python
# Generate large test datasets
routes = generate_mock_route_data(10000)
sessions = generate_mock_session_data(100)
```

## Contributing to Tests

When adding new tests:

1. **Follow Naming Conventions**: `test_*` functions, descriptive names
2. **Use Appropriate Markers**: Mark tests with correct categories
3. **Add Docstrings**: Explain what the test validates
4. **Mock External Dependencies**: Use fixtures for isolation
5. **Test Edge Cases**: Include boundary conditions and error cases
6. **Maintain Coverage**: Ensure new code has corresponding tests

### Example Test Structure

```python
@pytest.mark.unit
async def test_component_specific_behavior(mock_dependency, test_data):
    """Test that component behaves correctly under specific conditions."""
    # Arrange
    component = Component(mock_dependency)

    # Act
    result = await component.process(test_data)

    # Assert
    assert result.is_valid
    mock_dependency.method.assert_called_once_with(test_data)
```

## Troubleshooting

### Common Issues

1. **Database Connection Failures**: Ensure test database is running
2. **Import Errors**: Check PYTHONPATH includes project root
3. **Async Test Failures**: Ensure `pytest-asyncio` is installed
4. **Coverage Gaps**: Use `--cov-report=html` to identify missing coverage

### Test Environment Reset

```bash
# Clean all test artifacts
python run_tests.py --mode clean

# Reset database
docker rm -f test-timescaledb
# Recreate database container
```

## Resources

- [pytest Documentation](https://docs.pytest.org/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)
- [pytest-cov](https://pytest-cov.readthedocs.io/)
- [Bandit Security Linter](https://bandit.readthedocs.io/)
- [Safety Vulnerability Scanner](https://pyup.io/safety/)