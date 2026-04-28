#!/usr/bin/env bash
set -euo pipefail

echo "==================================="
echo "IDOR + JWT Demo - Java Version"
echo "==================================="
echo ""

MODE="${MODE:-VULN}"
echo "Starting docker-compose-java.yml with MODE=${MODE}"
echo ""

docker compose -f docker-compose-java.yml up -d --build

echo ""
echo "Waiting for application health..."
for i in {1..30}; do
  if curl -fsS "http://localhost:5001/health" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

curl -fsS "http://localhost:5001/health" || true

echo ""
echo "Up. Logs:"
docker compose -f docker-compose-java.yml logs -n 50 web