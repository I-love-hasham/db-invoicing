#!/usr/bin/env bash
# Monthly patch day / after you merge a PR: pull the approved code and rebuild.
set -euo pipefail
cd "$(dirname "$0")/.."
git pull --ff-only
export BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
docker compose build --pull
docker compose up -d
docker image prune -f
echo "Updated. Open Security Status in the app to check for open vulnerabilities."
