#!/usr/bin/env bash
set -euo pipefail

PORT="${TEST_PORT:-18080}"
HOST="${TEST_HOST:-127.0.0.1}"
JWT_SECRET="smoke-test-secret-0123456789abcdef"
TEST_USER="smoke_user_$(date +%s)"
TEST_EMAIL="${TEST_USER}@efarm.local"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  /opt/homebrew/opt/mysql@8.0/bin/mysql -h 127.0.0.1 -P 3306 -u root -proot -D smartfarm_db \
    -e "DELETE FROM users WHERE username = '${TEST_USER}';" >/dev/null 2>&1 || true
}
trap cleanup EXIT

HOST="$HOST" PORT="$PORT" \
  DB_DRIVER=mysql MYSQL_HOST=127.0.0.1 MYSQL_PORT=3306 \
  MYSQL_USER=root MYSQL_PASSWORD=root MYSQL_DB=smartfarm_db \
  JWT_SECRET="$JWT_SECRET" PBKDF2_ITERATIONS=10000 \
  ./bin/auth_server >/tmp/auth_smoke.log 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null; then
    break
  fi
  sleep 0.1
done

BASE="http://127.0.0.1:${PORT}"

# 1. Health check
HEALTH=$(curl -sf "${BASE}/health")
echo "Health: ${HEALTH}"

# 2. Register a new user in smartfarm_db.users
REG_RESP=$(curl -sf -X POST "${BASE}/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USER}\",\"password\":\"Password123\",\"full_name\":\"Smoke Test User\",\"email\":\"${TEST_EMAIL}\",\"phone\":\"012000111\",\"role\":\"staff\"}")
echo "Register: ${REG_RESP}"

# 3. Login with the newly registered user
LOGIN_NEW_RESP=$(curl -sf -X POST "${BASE}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USER}\",\"password\":\"Password123\"}")
echo "Login (new user): ${LOGIN_NEW_RESP}"

# 4. Login with existing smartfarm_db user (admin)
LOGIN_RESP=$(curl -sf -X POST "${BASE}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}')
echo "Login (admin): ${LOGIN_RESP}"

ACCESS_TOKEN=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["access_token"])' "$LOGIN_RESP")
REFRESH_TOKEN=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["refresh_token"])' "$LOGIN_RESP")

# 5. Protected /me
ME_RESP=$(curl -sf "${BASE}/api/auth/me" -H "Authorization: Bearer ${ACCESS_TOKEN}")
echo "Me: ${ME_RESP}"

# 6. Refresh rotation
REFRESH_RESP=$(curl -sf -X POST "${BASE}/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"${REFRESH_TOKEN}\"}")
NEW_REFRESH=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["refresh_token"])' "$REFRESH_RESP")

# 7. Logout
LOGOUT_RESP=$(curl -sf -X POST "${BASE}/api/auth/logout" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"${NEW_REFRESH}\"}")
echo "Logout: ${LOGOUT_RESP}"

# 8. Verify revoked token is rejected with 401
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/api/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"${NEW_REFRESH}\"}")
if [[ "$STATUS" != "401" ]]; then
  echo "Expected 401 after logout, got ${STATUS}"
  exit 1
fi

echo "MySQL register & login smoke test passed!"
