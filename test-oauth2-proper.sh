#!/bin/bash

# OAuth2 Endpoint Testing Script with Proper Authentication
# Tests OAuth2 flows with correct authentication and parameters

BASE_URL="http://localhost:8085"
CLIENT_ID="smartdrive-web"
CLIENT_SECRET="smartdrive-web-secret"
REDIRECT_URI="http://localhost:3000/callback"

echo "🔐 SmartDrive OAuth2 Proper Authentication Testing"
echo "=================================================="
echo "Testing URL: $BASE_URL"
echo "Client ID: $CLIENT_ID"
echo "Timestamp: $(date)"
echo ""

# Function to test endpoint and log results
test_oauth2_endpoint() {
    local endpoint=$1
    local method=${2:-GET}
    local data=${3:-""}
    local auth_header=${4:-""}
    local description=$5
    
    echo "🔍 Testing: $description"
    echo "   Endpoint: $method $endpoint"
    
    local curl_cmd="curl -s -w '\n%{http_code}' -X $method '$BASE_URL$endpoint'"
    
    if [ -n "$auth_header" ]; then
        curl_cmd="$curl_cmd -H '$auth_header'"
    fi
    
    if [ "$method" = "POST" ] && [ -n "$data" ]; then
        curl_cmd="$curl_cmd -H 'Content-Type: application/x-www-form-urlencoded' -d '$data'"
    fi
    
    response=$(eval $curl_cmd 2>/dev/null)
    
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
test_oauth2_endpoint "$AUTH_URL" "GET" "" "" "Authorization Request with Parameters"

# 2. Test Token Endpoint with proper Basic Authentication
echo "🎫 OAUTH2 TOKEN ENDPOINT"
echo "========================"

# Create Basic Auth header
BASIC_AUTH="Authorization: Basic $(echo -n 'smartdrive-web:smartdrive-web-secret' | base64)"

# Authorization Code Flow (with invalid code for testing)
AUTH_CODE_DATA="grant_type=authorization_code&code=invalid_code&redirect_uri=$REDIRECT_URI"
test_oauth2_endpoint "/oauth2/token" "POST" "$AUTH_CODE_DATA" "$BASIC_AUTH" "Authorization Code Flow with Basic Auth"

# 3. Test Token Introspection with Basic Auth
echo "🔍 TOKEN INTROSPECTION"
echo "======================"

INTROSPECT_DATA="token=invalid_token"
test_oauth2_endpoint "/oauth2/introspect" "POST" "$INTROSPECT_DATA" "$BASIC_AUTH" "Token Introspection with Basic Auth"

# 4. Test Token Revocation with Basic Auth
echo "🗑️  TOKEN REVOCATION"
echo "===================="

REVOKE_DATA="token=invalid_token"
test_oauth2_endpoint "/oauth2/revoke" "POST" "$REVOKE_DATA" "$BASIC_AUTH" "Token Revocation with Basic Auth"

# 5. Test OAuth2 Endpoints without parameters (should return proper error messages)
echo "🔧 OAUTH2 ENDPOINT VALIDATION"
echo "============================="

test_oauth2_endpoint "/oauth2/authorize" "GET" "" "" "Authorization Endpoint (No Parameters)"
test_oauth2_endpoint "/oauth2/token" "POST" "" "" "Token Endpoint (No Parameters)"

echo "🎯 OAUTH2 PROPER AUTHENTICATION TESTING COMPLETED"
echo "================================================="
