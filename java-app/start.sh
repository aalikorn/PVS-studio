#!/bin/bash

# Start script for Java IDOR/JWT demo application

set -e

echo "==================================="
echo "IDOR + JWT Demo - Java Version"
echo "==================================="
echo ""

# Check if MODE is set
if [ -z "$MODE" ]; then
    echo "MODE environment variable not set. Using default: VULN"
    export MODE=VULN
fi

echo "Starting application in $MODE mode..."
echo ""

# Check if docker-compose is available
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed or not in PATH"
    exit 1
fi

# Start with docker-compose
docker-compose -f docker-compose-java.yml up --build

echo ""
echo "Application stopped."
