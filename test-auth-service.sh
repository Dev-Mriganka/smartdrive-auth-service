#!/bin/bash

# Test Auth Service Endpoints
echo "🧪 Testing SmartDrive Auth Service"
echo "=================================="

# Base URL
BASE_URL="http://localhost:8085"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to test endpoint
test_endpoint() {
    local method=$1
    local endpoint=$2
    local data=$3
    local description=$4
    
    echo -e "\n${YELLOW}Testing: $description${NC}"
    echo "Endpoint: $method $BASE_URL$endpoint"
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$BASE_URL$endpoint")
    elif [ "$method" = "POST" ]; then
        response=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" -d "$data" "$BASE_URL$endpoint")
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]; then
        echo -e "${GREEN}✅ Success (HTTP $http_code)${NC}"
        echo "Response: $body"
    else
        echo -e "${RED}❌ Failed (HTTP $http_code)${NC}"
        echo "Response: $body"
    fi
}

# Test 1: Health Check
test_endpoint "GET" "/actuator/health" "" "Health Check"

# Test 2: User Registration
REGISTER_DATA='{
    "username": "testuser",
    "email": "test@smartdrive.com",
    "password": "TestPassword123!",
    "firstName": "Test",
    "lastName": "User"
}'
test_endpoint "POST" "/api/auth/register" "$REGISTER_DATA" "User Registration"

# Test 3: User Login
LOGIN_DATA='{
    "usernameOrEmail": "testuser",
    "password": "TestPassword123!",
    "clientId": "smartdrive-web"
}'
test_endpoint "POST" "/api/auth/login" "$LOGIN_DATA" "User Login"

# Test 4: OAuth2 Authorization Endpoint
test_endpoint "GET" "/oauth2/authorize?response_type=code&client_id=smartdrive-web&redirect_uri=http://localhost:3000/callback&scope=read%20write&state=test123" "" "OAuth2 Authorization"

echo -e "\n${GREEN}🎉 Auth Service Testing Complete!${NC}"

