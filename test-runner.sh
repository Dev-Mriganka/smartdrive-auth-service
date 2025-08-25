#!/bin/bash

# Auth Service Test Runner
# This script runs comprehensive tests for the Auth Service

set -e

echo "🚀 Starting Auth Service Test Suite"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the auth-service directory
if [ ! -f "build.gradle" ]; then
    print_error "Please run this script from the auth-service directory"
    exit 1
fi

# Check if Docker is running (needed for test containers)
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

print_status "Checking prerequisites..."

# Check Java version
JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2 | cut -d'.' -f1)
if [ "$JAVA_VERSION" -lt "17" ]; then
    print_error "Java 17 or higher is required. Current version: $JAVA_VERSION"
    exit 1
fi
print_success "Java version: $(java -version 2>&1 | head -n 1)"

# Check Gradle
if ! command -v ./gradlew &> /dev/null; then
    print_error "Gradle wrapper not found. Please ensure gradlew is present."
    exit 1
fi
print_success "Gradle wrapper found"

print_status "Cleaning previous build..."
./gradlew clean

print_status "Running unit tests..."
./gradlew test --tests "*UnitTest" --info

if [ $? -eq 0 ]; then
    print_success "Unit tests passed!"
else
    print_error "Unit tests failed!"
    exit 1
fi

print_status "Running integration tests..."
./gradlew test --tests "*IntegrationTest" --info

if [ $? -eq 0 ]; then
    print_success "Integration tests passed!"
else
    print_error "Integration tests failed!"
    exit 1
fi

print_status "Running security tests..."
./gradlew test --tests "*Security*" --info

if [ $? -eq 0 ]; then
    print_success "Security tests passed!"
else
    print_error "Security tests failed!"
    exit 1
fi

print_status "Running end-to-end tests..."
./gradlew test --tests "*EndToEnd*" --info

if [ $? -eq 0 ]; then
    print_success "End-to-end tests passed!"
else
    print_error "End-to-end tests failed!"
    exit 1
fi

print_status "Running performance tests..."
./gradlew test --tests "*Performance*" --info

if [ $? -eq 0 ]; then
    print_success "Performance tests passed!"
else
    print_warning "Performance tests failed or had issues"
fi

print_status "Running all tests..."
./gradlew test --info

if [ $? -eq 0 ]; then
    print_success "All tests passed! 🎉"
else
    print_error "Some tests failed!"
    exit 1
fi

print_status "Generating test report..."
./gradlew test --tests "*" --info 2>&1 | tee test-results.log

print_status "Test Summary:"
echo "=================="
echo "✅ Unit Tests: JWT Service, OAuth2 Service"
echo "✅ Integration Tests: OAuth2 Controller"
echo "✅ Security Tests: Configuration, CORS, Authentication"
echo "✅ End-to-End Tests: Complete OAuth2 Flows"
echo "✅ Performance Tests: Load Testing, Concurrent Requests"
echo ""
print_success "Auth Service is ready for production! 🚀"

# Optional: Generate coverage report
if command -v jacoco &> /dev/null; then
    print_status "Generating coverage report..."
    ./gradlew jacocoTestReport
    print_success "Coverage report generated in build/reports/jacoco/test/html/index.html"
fi

echo ""
echo "📊 Test Results Summary:"
echo "========================"
echo "📁 Test reports: build/reports/tests/test/index.html"
echo "📁 Coverage report: build/reports/jacoco/test/html/index.html"
echo "📁 Test logs: test-results.log"
echo ""
echo "🔍 To view detailed results:"
echo "   - Open build/reports/tests/test/index.html in your browser"
echo "   - Check test-results.log for detailed output"
echo ""
print_success "Auth Service testing completed successfully! 🎯"
