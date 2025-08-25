#!/bin/bash

# Comprehensive Auth Service Endpoint Testing Script
# Tests all endpoints and provides detailed status report

BASE_URL="http://localhost:8085"
LOG_FILE="endpoint-test-results.log"

echo "🧪 SmartDrive Auth Service - Comprehensive Endpoint Testing" | tee $LOG_FILE
echo "================================================================" | tee -a $LOG_FILE
echo "Testing URL: $BASE_URL" | tee -a $LOG_FILE
echo "Timestamp: $(date)" | tee -a $LOG_FILE
echo "" | tee -a $LOG_FILE

# Function to test endpoint and log results
test_endpoint() {
    local endpoint=$1
    local method=${2:-GET}
    local data=${3:-""}
    local description=$4
    
    echo "🔍 Testing: $description" | tee -a $LOG_FILE
    echo "   Endpoint: $method $endpoint" | tee -a $LOG_FILE
    
    if [ "$method" = "POST" ] && [ -n "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X $method "$BASE_URL$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data" 2>/dev/null)
    else
        response=$(curl -s -w "\n%{http_code}" -X $method "$BASE_URL$endpoint" 2>/dev/null)
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
        echo "   ✅ Status: $http_code - SUCCESS" | tee -a $LOG_FILE
        echo "   📄 Response: $(echo "$body" | head -c 100)..."
    elif [ "$http_code" -ge 400 ] && [ "$http_code" -lt 500 ]; then
        echo "   ⚠️  Status: $http_code - CLIENT ERROR" | tee -a $LOG_FILE
        echo "   📄 Response: $(echo "$body" | head -c 100)..."
    elif [ "$http_code" -ge 500 ]; then
        echo "   ❌ Status: $http_code - SERVER ERROR" | tee -a $LOG_FILE
        echo "   📄 Response: $(echo "$body" | head -c 100)..."
    else
        echo "   ❓ Status: $http_code - UNKNOWN" | tee -a $LOG_FILE
    fi
    echo "" | tee -a $LOG_FILE
}

# 1. Health and Basic Endpoints
echo "🏥 HEALTH & BASIC ENDPOINTS" | tee -a $LOG_FILE
echo "==========================" | tee -a $LOG_FILE

test_endpoint "/actuator/health" "GET" "" "Health Check"
test_endpoint "/actuator/info" "GET" "" "Application Info"
test_endpoint "/actuator/metrics" "GET" "" "Metrics Endpoint"

# 2. OpenID Connect Discovery Endpoints
echo "🔍 OPENID CONNECT DISCOVERY" | tee -a $LOG_FILE
echo "===========================" | tee -a $LOG_FILE

test_endpoint "/.well-known/openid_configuration" "GET" "" "OIDC Discovery"
test_endpoint "/.well-known/jwks.json" "GET" "" "JSON Web Key Set"
test_endpoint "/.well-known/userinfo" "GET" "" "User Info Endpoint"

# 3. OAuth2 Authorization Server Endpoints
echo "🔐 OAUTH2 AUTHORIZATION SERVER" | tee -a $LOG_FILE
echo "==============================" | tee -a $LOG_FILE

test_endpoint "/oauth2/authorize" "GET" "" "Authorization Endpoint"
test_endpoint "/oauth2/token" "POST" "" "Token Endpoint"
test_endpoint "/oauth2/introspect" "POST" "" "Token Introspection"
test_endpoint "/oauth2/revoke" "POST" "" "Token Revocation"

# 4. Client Registration Endpoints
echo "📝 CLIENT REGISTRATION" | tee -a $LOG_FILE
echo "======================" | tee -a $LOG_FILE

test_endpoint "/api/v1/clients/register-defaults" "POST" "" "Register Default Clients"
test_endpoint "/api/v1/clients/smartdrive-web" "GET" "" "Get Web Client Info"
test_endpoint "/api/v1/clients/list" "GET" "" "List All Clients"
test_endpoint "/api/v1/clients/test-credentials" "GET" "" "Test Credentials"

# 5. User Management Endpoints
echo "👤 USER MANAGEMENT" | tee -a $LOG_FILE
echo "==================" | tee -a $LOG_FILE

# Test user registration
REGISTER_DATA='{
  "username": "testuser",
  "email": "test@example.com",
  "password": "TestPassword123!",
  "confirmPassword": "TestPassword123!",
  "firstName": "Test",
  "lastName": "User",
  "phoneNumber": "+1234567890",
  "bio": "Test user for endpoint testing"
}'

test_endpoint "/api/v1/users/register" "POST" "$REGISTER_DATA" "User Registration"

# Test user profile update
UPDATE_DATA='{
  "firstName": "Updated",
  "lastName": "User",
  "phoneNumber": "+1234567890",
  "bio": "Updated bio for testing"
}'

test_endpoint "/api/v1/users/profile" "PUT" "$UPDATE_DATA" "Update User Profile"

# Test password change
PASSWORD_DATA='{
  "currentPassword": "TestPassword123!",
  "newPassword": "NewPassword123!",
  "confirmNewPassword": "NewPassword123!"
}'

test_endpoint "/api/v1/users/change-password" "POST" "$PASSWORD_DATA" "Change Password"

# Test user retrieval
test_endpoint "/api/v1/users/testuser" "GET" "" "Get User by Username"
test_endpoint "/api/v1/users/email/test@example.com" "GET" "" "Get User by Email"
test_endpoint "/api/v1/users" "GET" "" "Get All Users"
test_endpoint "/api/v1/users/statistics" "GET" "" "User Statistics"

# 6. Social Login Endpoints
echo "🌐 SOCIAL LOGIN" | tee -a $LOG_FILE
echo "===============" | tee -a $LOG_FILE

test_endpoint "/api/v1/social/accounts" "GET" "" "Get User Social Accounts"
test_endpoint "/api/v1/social/providers" "GET" "" "Get Available Providers"
test_endpoint "/api/v1/social/status" "GET" "" "Get Social Login Status"

# 7. Swagger/OpenAPI Documentation
echo "📚 API DOCUMENTATION" | tee -a $LOG_FILE
echo "====================" | tee -a $LOG_FILE

test_endpoint "/swagger-ui/index.html" "GET" "" "Swagger UI"
test_endpoint "/v3/api-docs" "GET" "" "OpenAPI Specification"
test_endpoint "/v3/api-docs/openapi.json" "GET" "" "OpenAPI JSON"

# 8. OAuth2 Authorization Flow Test
echo "🔄 OAUTH2 AUTHORIZATION FLOW" | tee -a $LOG_FILE
echo "============================" | tee -a $LOG_FILE

# Test authorization request
test_endpoint "/oauth2/authorize?response_type=code&client_id=smartdrive-web&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email&state=test123" "GET" "" "Authorization Request"

# Test token request with authorization code (this will fail without valid code)
TOKEN_DATA='grant_type=authorization_code&client_id=smartdrive-web&client_secret=smartdrive-web-secret&code=invalid_code&redirect_uri=http://localhost:3000/callback'

test_endpoint "/oauth2/token" "POST" "$TOKEN_DATA" "Token Request (with invalid code)"

# Test client credentials flow
CLIENT_CREDENTIALS_DATA='grant_type=client_credentials&client_id=smartdrive-web&client_secret=smartdrive-web-secret'

test_endpoint "/oauth2/token" "POST" "$CLIENT_CREDENTIALS_DATA" "Client Credentials Flow"

echo "" | tee -a $LOG_FILE
echo "🎯 TESTING COMPLETED" | tee -a $LOG_FILE
echo "===================" | tee -a $LOG_FILE
echo "📋 Results saved to: $LOG_FILE" | tee -a $LOG_FILE
echo "🔍 Check the log file for detailed results" | tee -a $LOG_FILE
