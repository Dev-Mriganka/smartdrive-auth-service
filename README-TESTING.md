# Auth Service Testing Guide

## 🚀 Overview

This document provides comprehensive testing information for the SmartDrive Auth Service, which implements a full OAuth2 authorization server with JWT token management.

## 📋 Test Categories

### 1. Unit Tests
- **JWT Service Tests**: Token generation, validation, and parsing
- **OAuth2 Service Tests**: Core OAuth2 business logic
- **User Service Tests**: User management functionality

### 2. Integration Tests
- **OAuth2 Controller Tests**: API endpoint testing with mocked services
- **Database Integration**: Repository layer testing
- **Redis Integration**: Caching and session management

### 3. End-to-End Tests
- **Complete OAuth2 Flows**: Authorization code, refresh token, client credentials
- **Token Lifecycle**: Generation, validation, introspection, revocation
- **Error Handling**: Invalid requests, expired tokens, malformed data

### 4. Security Tests
- **Authentication**: Endpoint access control
- **CORS Configuration**: Cross-origin request handling
- **Input Validation**: Request parameter validation
- **Token Security**: JWT signature verification

### 5. Performance Tests
- **Load Testing**: High-volume token generation
- **Concurrent Requests**: Multi-threaded testing
- **Response Time**: Performance benchmarking

## 🛠️ Test Setup

### Prerequisites
- Java 17 or higher
- Docker (for test containers)
- Gradle wrapper

### Test Configuration
- **Test Profile**: `application-test.yml`
- **Database**: PostgreSQL test container
- **Cache**: Redis test container
- **Logging**: `logback-test.xml`

## 🏃‍♂️ Running Tests

### Quick Start
```bash
# Run all tests
./test-runner.sh

# Or use Gradle directly
./gradlew test
```

### Individual Test Categories
```bash
# Unit tests only
./gradlew test --tests "*UnitTest"

# Integration tests only
./gradlew test --tests "*IntegrationTest"

# End-to-end tests only
./gradlew test --tests "*EndToEnd*"

# Security tests only
./gradlew test --tests "*Security*"

# Performance tests only
./gradlew test --tests "*Performance*"
```

### Test Reports
```bash
# Generate HTML test report
./gradlew test --tests "*" --info

# Generate coverage report
./gradlew jacocoTestReport
```

## 📊 Test Coverage

### OAuth2 Endpoints Tested
- ✅ `/oauth2/authorize` - Authorization endpoint
- ✅ `/oauth2/token` - Token endpoint
- ✅ `/oauth2/userinfo` - User info endpoint
- ✅ `/oauth2/introspect` - Token introspection
- ✅ `/oauth2/revoke` - Token revocation
- ✅ `/oauth2/register` - Client registration
- ✅ `/oauth2/.well-known/oauth-authorization-server` - Discovery
- ✅ `/oauth2/jwks` - JSON Web Key Set
- ✅ `/oauth2/error` - Error handling

### OAuth2 Flows Tested
- ✅ Authorization Code Flow
- ✅ Refresh Token Flow
- ✅ Client Credentials Flow
- ✅ Token Introspection
- ✅ Token Revocation

### Security Features Tested
- ✅ JWT Token Generation & Validation
- ✅ Client Authentication
- ✅ CORS Configuration
- ✅ Input Validation
- ✅ Error Handling
- ✅ Rate Limiting (if configured)

## 🔧 Test Configuration

### Test Properties
```yaml
# application-test.yml
server:
  port: 0  # Random port for testing

spring:
  datasource:
    url: jdbc:tc:postgresql:15:///testdb
  data:
    redis:
      host: localhost
      port: 6379

app:
  jwt:
    secret: test-secret-key-for-testing-purposes-only-256-bits-long
    expiration: 3600000  # 1 hour
```

### Test Containers
- **PostgreSQL**: `postgres:15`
- **Redis**: `redis:7-alpine`

## 📈 Performance Benchmarks

### Expected Performance
- **Token Generation**: < 100ms average
- **Token Validation**: < 50ms average
- **Concurrent Requests**: 100+ requests/second
- **Memory Usage**: < 512MB under load

### Performance Test Scenarios
1. **Sequential Token Generation**: 100 tokens
2. **Concurrent Token Generation**: 10 threads × 10 requests
3. **Token Validation**: 100 validations
4. **Mixed Load**: Authorization + Token + UserInfo

## 🐛 Troubleshooting

### Common Issues

#### Docker Not Running
```bash
# Start Docker
sudo systemctl start docker
# or
sudo service docker start
```

#### Test Container Issues
```bash
# Clean up containers
docker system prune -f
# Restart Docker
sudo systemctl restart docker
```

#### Memory Issues
```bash
# Increase JVM memory for tests
./gradlew test -Dorg.gradle.jvmargs="-Xmx2g"
```

#### Database Connection Issues
```bash
# Check if PostgreSQL container is running
docker ps | grep postgres
# Check container logs
docker logs <container-id>
```

### Debug Mode
```bash
# Run tests with debug logging
./gradlew test --debug

# Run specific test with debug
./gradlew test --tests "OAuth2ControllerIntegrationTest" --debug
```

## 📝 Test Data

### Test Users
- Username: `testuser`
- Email: `test@example.com`
- Roles: `USER`

### Test Clients
- Client ID: `test-client`
- Client Secret: `test-secret`
- Redirect URI: `http://localhost:3000/callback`

### Test Scopes
- `read` - Read access
- `write` - Write access
- `admin` - Administrative access

## 🔍 Monitoring & Observability

### Test Metrics
- Response times
- Success/failure rates
- Memory usage
- CPU usage
- Database connection pool

### Health Checks
- Application health: `/actuator/health`
- Database health: Connection pool status
- Redis health: Cache connectivity

## 🚨 Security Considerations

### Test Environment Security
- Use test-specific JWT secrets
- Isolated test databases
- No production data in tests
- Secure test credentials

### OAuth2 Security Testing
- Token expiration validation
- Client authentication
- Scope validation
- Redirect URI validation
- PKCE support (if implemented)

## 📚 Additional Resources

### OAuth2 Specification
- [RFC 6749](https://tools.ietf.org/html/rfc6749) - OAuth 2.0 Authorization Framework
- [RFC 6750](https://tools.ietf.org/html/rfc6750) - OAuth 2.0 Bearer Token Usage
- [RFC 7662](https://tools.ietf.org/html/rfc7662) - OAuth 2.0 Token Introspection

### JWT Specification
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JSON Web Token (JWT)

### Testing Best Practices
- [Spring Boot Testing](https://spring.io/guides/gs/testing-web/)
- [TestContainers](https://www.testcontainers.org/)
- [JUnit 5](https://junit.org/junit5/)

## 🤝 Contributing

### Adding New Tests
1. Follow naming convention: `*Test.java`
2. Use appropriate test categories
3. Include proper assertions
4. Add documentation
5. Update this guide

### Test Naming Convention
- Unit Tests: `*Test.java`
- Integration Tests: `*IntegrationTest.java`
- End-to-End Tests: `*EndToEndTest.java`
- Security Tests: `*SecurityTest.java`
- Performance Tests: `*PerformanceTest.java`

---

**Note**: This testing suite ensures the Auth Service is production-ready with comprehensive coverage of all OAuth2 flows, security features, and performance requirements.
