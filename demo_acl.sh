#!/usr/bin/env bash
# Web SSL VPN — Access Control Demo
# 
# Shows authorized and unauthorized proxy access:
#   admin  → all 4 apps (role-based bypass)
#   alice  → only Wiki (permission-based)
#   bob    → no apps at all
#
# Prerequisite: zig build run (server must be running on :8443)
set -euo pipefail
cd "$(dirname "$0")"

BASE="${1:-https://localhost:8443}"
CURL="curl -sk --max-time 10"

echo "=========================================="
echo "  Web SSL VPN — Access Control Demo"
echo "=========================================="
echo ""

# ─── Admin login ───────────────────────────
echo "■ Step 1 — Admin login (role-based bypass)"
ADMIN_COOKIE=$(mktemp)
$CURL -c "$ADMIN_COOKIE" -X POST "$BASE/api/auth/login" \
    -H "Content-Type: application/json" \
    -H "Origin: $BASE" \
    -d '{"username":"admin","password":"admin123"}' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  ✓ {d[\"data\"][\"username\"]} ({d[\"data\"][\"role\"]}) — {len(d[\"data\"][\"apps\"])} apps')" 2>/dev/null \
    || $CURL -c "$ADMIN_COOKIE" -X POST "$BASE/api/auth/login" \
      -H "Content-Type: application/json" \
      -H "Origin: $BASE" \
      -d '{"username":"admin","password":"admin123"}'
echo ""

# ─── Admin proxies all 4 apps ──────────────
echo "■ Step 2 — Admin proxy access (all apps)"
for id in 1 2 3 4; do
    TITLE=$($CURL -b "$ADMIN_COOKIE" "$BASE/proxy/$id" 2>/dev/null | grep -oP '<title>\K[^<]*' || echo "FAIL")
    echo "  proxy/$id → $TITLE"
done
echo ""

# ─── Create alice (user) ───────────────────
echo "■ Step 3 — Create user 'alice'"
$CURL -b "$ADMIN_COOKIE" -X POST "$BASE/api/users" \
    -H "Content-Type: application/json" \
    -H "Origin: $BASE" \
    -d '{"username":"alice","password":"alice123","role":"user"}' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  ✓ {d[\"data\"][\"username\"]} (id={d[\"data\"][\"id\"]}, {d[\"data\"][\"role\"]})')" 2>/dev/null \
    || true
echo ""

# ─── Grant alice Wiki only ─────────────────
echo "■ Step 4 — Grant alice: Wiki only (app_id=1)"
$CURL -b "$ADMIN_COOKIE" -X PUT "$BASE/api/users/2/permissions" \
    -H "Content-Type: application/json" \
    -H "Origin: $BASE" \
    -d '[1]' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  ✓ success={d[\"success\"]}')" 2>/dev/null \
    || true
echo ""

# ─── Alice login ───────────────────────────
echo "■ Step 5 — Alice login"
ALICE_COOKIE=$(mktemp)
$CURL -c "$ALICE_COOKIE" -X POST "$BASE/api/auth/login" \
    -H "Content-Type: application/json" \
    -H "Origin: $BASE" \
    -d '{"username":"alice","password":"alice123"}' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  ✓ {d[\"data\"][\"username\"]} ({d[\"data\"][\"role\"]}) — {len(d[\"data\"][\"apps\"])} apps')" 2>/dev/null \
    || $CURL -c "$ALICE_COOKIE" -X POST "$BASE/api/auth/login" \
      -H "Content-Type: application/json" \
      -H "Origin: $BASE" \
      -d '{"username":"alice","password":"alice123"}'
echo ""

# ─── Alice authorized access ───────────────
echo "■ Step 6 — Alice: AUTHORIZED (Wiki=id 1)"
TITLE=$($CURL -b "$ALICE_COOKIE" "$BASE/proxy/1" 2>/dev/null | grep -oP '<title>\K[^<]*' || echo "FAIL")
echo "  proxy/1 → $TITLE  ✓ AUTHORIZED"
echo ""

# ─── Alice denied access ───────────────────
echo "■ Step 7 — Alice: DENIED (Mail=id 2, HR=id 4)"
for id in 2 4; do
    RESULT=$($CURL -o /dev/null -w "%{http_code}" -b "$ALICE_COOKIE" "$BASE/proxy/$id" 2>/dev/null || echo "000")
    case "$RESULT" in
        403) echo "  proxy/$id → 403 Forbidden  ✗ ACCESS DENIED" ;;
        000) echo "  proxy/$id → connection refused" ;;
        *)   echo "  proxy/$id → HTTP $RESULT" ;;
    esac
done
echo ""

# ─── Audit log ─────────────────────────────
echo "■ Step 8 — Admin views audit log"
$CURL -b "$ADMIN_COOKIE" "$BASE/api/audit" 2>/dev/null \
    | python3 -c "
import sys,json
d=json.load(sys.stdin)
for e in d['data'][-6:]:
    print(f'  [{e[\"timestamp\"][:19]}] {e[\"username\"]:8s} {e[\"action\"]:15s} → {e[\"result\"]}')
" 2>/dev/null || true
echo ""

# ─── Cleanup ───────────────────────────────
rm -f "$ADMIN_COOKIE" "$ALICE_COOKIE"
echo "=========================================="
echo "  Summary"
echo "  admin → role=admin → all apps (bypass)"
echo "  alice → role=user  → only Wiki (id=1)"
echo "  alice → Mail/HR    → 403 Access Denied"
echo "=========================================="
