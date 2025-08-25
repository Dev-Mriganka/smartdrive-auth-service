#!/bin/bash

# OAuth2 Endpoint Testing Script with Proper Parameters
# Tests OAuth2 flows with correct parameters

BASE_URL="http://localhost:8085"
CLIENT_ID="smartdrive-web"
CLIENT_SECRET="smartdrive-web-secret"
REDIRECT_URI="http://localhost:3000/callback"

echo "🔐 SmartDrive OAuth2 Endpoint Testing with Proper Parameters"
echo "============================================================="
echo "Testing URL: $BASE_URL"
echo "Client ID: $CLIENT_ID"
echo "Timestamp: $(date)"
echo ""

# Function to test endpoint and log results
test_oauth2_endpoint() {
    local endpoint=$1
    local method=${2:-GET}
    local data=${3:-""}
    local description=$4
    
    echo "🔍 Testing: $description"
    echo "   Endpoint: $method $endpoint"
    
    if [ "$method" = "POST" ] && [ -n "$data" ]; then
        response=$(curl -s -w "\n%{http_code}" -X $method "$BASE_URL$endpoint" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "$data" 2>/dev/null)
    else
        response=$(curl -s -w "\n%{http_code}" -X $method "$BASE_URL$endpoint" 2>/dev/null)
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
        echo "   ✅ Status: $http_code - SUCCESS"
        echo "   📄 Response: $(echo "$body" | head -c 200)..."
    elif [ "$http_code" -ge 400 ] && [ "$http_code" -lt 500 ]; then
        echo "   ⚠️  Status: $http_code - CLIENT ERROR"
        echo "   📄 Response: $(echo "$body" | head -c 200)..."
    elif [ "$http_code" -ge 500 ]; then
        echo "   ❌ Status: $http_code - SERVER ERROR"
        echo "   📄 Response: $(echo "$body" | head -c 200)..."
    else
        echo "   ❓ Status: $http_code - UNKNOWN"
    fi
    echo ""
}

# 1. Test Authorization Endpoint with proper parameters
echo "🔐 OAUTH2 AUTHORIZATION ENDPOINT"
echo "================================"

AUTH_URL="/oauth2/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid%20profile%20email&state=test123"
test_oauth2_endpoint "$AUTH_URL" "GET" "" "Authorization Request with Parameters"

# 2. Test Token Endpoint with client credentials flow
echo "🎫 OAUTH2 TOKEN ENDPOINT"
echo "========================"

# Client Credentials Flow
CLIENT_CREDENTIALS_DATA="grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET"
test_oauth2_endpoint "/oauth2/token" "POST" "$CLIENT_CREDENTIALS_DATA" "Client Credentials Flow"

# Authorization Code Flow (with invalid code for testing)
AUTH_CODE_DATA="grant_type=authorization_code&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&code=invalid_code&redirect_uri=$REDIRECT_URI"
test_oauth2_endpoint "/oauth2/token" "POST" "$AUTH_CODE_DATA" "Authorization Code Flow (Invalid Code)"

# 3. Test Token Introspection
echo "🔍 TOKEN INTROSPECTION"
echo "======================"

INTROSPECT_DATA="token=invalid_token"
test_oauth2_endpoint "/oauth2/introspect" "POST" "$INTROSPECT_DATA" "Token Introspection"

# 4. Test Token Revocation
echo "🗑️  TOKEN REVOCATION"
echo "===================="

REVOKE_DATA="token=invalid_token"
test_oauth2_endpoint "/oauth2/revoke" "POST" "$REVOKE_DATA" "Token Revocation"

# 5. Test OpenAPI Documentation
echo "📚 OPENAPI DOCUMENTATION"
echo "========================"

test_oauth2_endpoint "/v3/api-docs" "GET" "" "OpenAPI Specification"
test_oauth2_endpoint "/v3/api-docs/openapi.json" "GET" "" "OpenAPI JSON"

echo "🎯 OAUTH2 TESTING COMPLETED"
echo "==========================="
