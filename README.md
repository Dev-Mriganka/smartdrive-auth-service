# SmartDrive OAuth2.0 Authentication Service

A comprehensive OAuth2.0 and OpenID Connect authentication service built with Spring Boot, providing enterprise-grade authentication and authorization for the SmartDrive platform.

## 🚀 Features

### OAuth2.0 Flows Supported
- ✅ **Authorization Code Flow** (Most secure for web applications)
- ✅ **Client Credentials Flow** (Service-to-service authentication)
- ✅ **Password Grant** (For trusted clients)
- ✅ **Refresh Token Flow** (Token renewal)

### Security Features
- ✅ **JWT Tokens** (Access and Refresh tokens)
- ✅ **Role-Based Access Control** (RBAC)
- ✅ **PKCE Support** (Proof Key for Code Exchange)
- ✅ **Token Introspection** (RFC 7662)
- ✅ **Token Revocation** (RFC 7009)
- ✅ **Audit Logging** (Complete authentication events)
- ✅ **Rate Limiting** (Per-user and per-endpoint)

### User Management
- ✅ **User Registration** with email verification
- ✅ **Password Security** (BCrypt with strength 12)
- ✅ **Account Lockout** (After failed attempts)
- ✅ **Session Management** (Redis-based)
- ✅ **Multi-Factor Authentication** (Ready for implementation)

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   API Gateway   │    │   Auth Service  │
│   (Future)      │    │   (Port 8080)   │    │   (Port 8085)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │   Redis         │    │   Business      │
│   (User Data)   │    │   (Sessions)    │    │   Services      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📡 OAuth2.0 Endpoints

### Authorization Endpoint
```http
GET /oauth2/authorize
```

**Parameters:**
- `response_type` (required): "code"
- `client_id` (required): OAuth2 client identifier
- `redirect_uri` (required): Callback URL
- `scope` (optional): Requested scopes
- `state` (optional): CSRF protection
- `code_challenge` (optional): PKCE challenge
- `code_challenge_method` (optional): PKCE method (S256)

**Example:**
```bash
curl "http://localhost:8085/oauth2/authorize?response_type=code&client_id=smartdrive-web&redirect_uri=http://localhost:3000/callback&scope=read write&state=abc123"
```

### Token Endpoint
```http
POST /oauth2/token
```

**Authorization Code Grant:**
```bash
curl -X POST http://localhost:8085/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=smartdrive-web" \
  -d "client_secret=your-client-secret" \
  -d "code=authorization_code" \
  -d "redirect_uri=http://localhost:3000/callback"
```

**Password Grant:**
```bash
curl -X POST http://localhost:8085/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=smartdrive-api" \
  -d "client_secret=your-client-secret" \
  -d "username=user@example.com" \
  -d "password=password123" \
  -d "scope=read write"
```

**Refresh Token Grant:**
```bash
curl -X POST http://localhost:8085/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=smartdrive-web" \
  -d "client_secret=your-client-secret" \
  -d "refresh_token=your-refresh-token"
```

### UserInfo Endpoint
```http
GET /oauth2/userinfo
```

**Example:**
```bash
curl -H "Authorization: Bearer your-access-token" \
  http://localhost:8085/oauth2/userinfo
```

### Token Introspection Endpoint
```http
POST /oauth2/introspect
```

**Example:**
```bash
curl -X POST http://localhost:8085/oauth2/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=your-access-token" \
  -d "client_id=smartdrive-api" \
  -d "client_secret=your-client-secret"
```

### Token Revocation Endpoint
```http
POST /oauth2/revoke
```

**Example:**
```bash
curl -X POST http://localhost:8085/oauth2/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=your-access-token" \
  -d "client_id=smartdrive-web" \
  -d "client_secret=your-client-secret"
```

### Discovery Endpoint
```http
GET /.well-known/oauth-authorization-server
```

**Example:**
```bash
curl http://localhost:8085/.well-known/oauth-authorization-server
```

### JWKS Endpoint
```http
GET /oauth2/jwks
```

**Example:**
```bash
curl http://localhost:8085/oauth2/jwks
```

## 🔐 OAuth2.0 Clients

### Default Clients

#### 1. SmartDrive Web Client
- **Client ID**: `smartdrive-web`
- **Type**: Public
- **Grant Types**: authorization_code, refresh_token
- **Redirect URIs**: 
  - http://localhost:3000/callback
  - http://localhost:8080/callback
- **Scopes**: read, write

#### 2. SmartDrive API Client
- **Client ID**: `smartdrive-api`
- **Type**: Confidential
- **Grant Types**: client_credentials, password, refresh_token
- **Scopes**: read, write, admin

## 👥 User Roles

### Available Roles
- **SMARTDRIVE_ADMIN**: Full system access
- **SMARTDRIVE_USER**: Personal file management
- **SMARTDRIVE_VIEWER**: Read-only access
- **SMARTDRIVE_GUEST**: Limited access

### Default Users
- **Admin User**:
  - Username: `admin`
  - Email: `admin@smartdrive.com`
  - Password: `admin123`
  - Role: `SMARTDRIVE_ADMIN`

- **Test User**:
  - Username: `user`
  - Email: `user@smartdrive.com`
  - Password: `user123`
  - Role: `SMARTDRIVE_USER`

## 🛠️ Configuration

### Environment Variables

```bash
# Database Configuration
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=smartdrive_auth
POSTGRES_USER=keycloak
POSTGRES_PASSWORD=password

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379

# JWT Configuration
JWT_SECRET=your-256-bit-secret-key-here-make-it-long-and-secure-for-production
JWT_EXPIRATION=86400000
JWT_REFRESH_EXPIRATION=604800000

# Security Configuration
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
```

### Application Properties

```yaml
server:
  port: 8085

spring:
  application:
    name: auth-service
  
  datasource:
    url: jdbc:postgresql://${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}
    username: ${POSTGRES_USER}
    password: ${POSTGRES_PASSWORD}
  
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
  
  data:
    redis:
      host: ${REDIS_HOST}
      port: ${REDIS_PORT}

app:
  jwt:
    secret: ${JWT_SECRET}
    expiration: ${JWT_EXPIRATION}
    refresh-expiration: ${JWT_REFRESH_EXPIRATION}
    issuer: smartdrive-auth-service
  
  security:
    password:
      encoder:
        strength: 12
    cors:
      allowed-origins: ${CORS_ALLOWED_ORIGINS}
```

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Java 17+
- PostgreSQL
- Redis

### Local Development

1. **Start the services**
   ```bash
   docker compose up -d postgres redis
   ```

2. **Run the auth service**
   ```bash
   cd auth-service
   ./gradlew bootRun
   ```

3. **Test the endpoints**
   ```bash
   # Test health check
   curl http://localhost:8085/actuator/health
   
   # Test OAuth2 discovery
   curl http://localhost:8085/.well-known/oauth-authorization-server
   ```

### Docker Deployment

```bash
# Build and start all services
docker compose up -d

# View logs
docker compose logs -f auth-service

# Stop services
docker compose down
```

## 📊 Monitoring

### Health Checks
```bash
# Service health
curl http://localhost:8085/actuator/health

# Database health
curl http://localhost:8085/actuator/health/db

# Redis health
curl http://localhost:8085/actuator/health/redis
```

### Metrics
```bash
# Prometheus metrics
curl http://localhost:8085/actuator/prometheus

# Application metrics
curl http://localhost:8085/actuator/metrics
```

### Logs
```bash
# View service logs
docker compose logs -f auth-service

# Filter authentication events
docker compose logs auth-service | grep "AUTH"
```

## 🔒 Security Best Practices

### JWT Security
- **Secret Key**: Use a strong, randomly generated secret (256+ bits)
- **Token Expiration**: Short-lived access tokens (1 hour)
- **Refresh Tokens**: Longer-lived but revocable (7 days)
- **Token Storage**: Store in HttpOnly cookies or secure storage

### OAuth2.0 Security
- **PKCE**: Always use PKCE for public clients
- **State Parameter**: Use state parameter for CSRF protection
- **Redirect URIs**: Validate redirect URIs strictly
- **Scope Validation**: Validate requested scopes

### Database Security
- **Password Hashing**: BCrypt with strength 12
- **SQL Injection**: Use parameterized queries
- **Connection Security**: Use SSL/TLS for database connections

## 🧪 Testing

### Unit Tests
```bash
./gradlew test
```

### Integration Tests
```bash
./gradlew integrationTest
```

### OAuth2.0 Flow Testing
```bash
# 1. Get authorization code
curl "http://localhost:8085/oauth2/authorize?response_type=code&client_id=smartdrive-web&redirect_uri=http://localhost:3000/callback&scope=read write&state=test123"

# 2. Exchange code for token
curl -X POST http://localhost:8085/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&client_id=smartdrive-web&code=YOUR_CODE&redirect_uri=http://localhost:3000/callback"

# 3. Use access token
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  http://localhost:8085/oauth2/userinfo
```

## 📚 API Documentation

### Swagger UI
- **URL**: http://localhost:8085/swagger-ui.html
- **OpenAPI Spec**: http://localhost:8085/api-docs

### OAuth2.0 Documentation
- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 6750**: OAuth 2.0 Bearer Token Usage
- **RFC 7009**: OAuth 2.0 Token Revocation
- **RFC 7662**: OAuth 2.0 Token Introspection

## 🐛 Troubleshooting

### Common Issues

1. **Database Connection**
   ```bash
   # Check PostgreSQL is running
   docker compose ps postgres
   
   # Check database connection
   docker compose logs auth-service | grep "database"
   ```

2. **JWT Token Issues**
   ```bash
   # Validate token format
   echo "YOUR_TOKEN" | cut -d'.' -f2 | base64 -d | jq
   
   # Check token expiration
   curl -X POST http://localhost:8085/oauth2/introspect \
     -d "token=YOUR_TOKEN"
   ```

3. **Redis Connection**
   ```bash
   # Check Redis is running
   docker compose ps redis
   
   # Test Redis connection
   docker compose exec redis redis-cli ping
   ```

### Logs
```bash
# View all logs
docker compose logs auth-service

# Filter by log level
docker compose logs auth-service | grep "ERROR"

# Follow logs in real-time
docker compose logs -f auth-service
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
