#!/bin/bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0

check() {
    local label="$1"
    local result="$2"
    if [ "$result" = "ok" ]; then
        echo "  [PASS] $label"
        PASS=$((PASS+1))
    else
        echo "  [FAIL] $label — $result"
        FAIL=$((FAIL+1))
    fi
}

echo ""
echo "=== VCS SecureChat — Pre-flight Security Check ==="
echo ""

# 1. Binaries exist
[ -f build/vcs_server ] && check "vcs_server binary exists" "ok" \
    || check "vcs_server binary exists" "not found — run scripts/build.sh"
[ -f build/vcs_client ] && check "vcs_client binary exists" "ok" \
    || check "vcs_client binary exists" "not found"

# 2. Binaries not debug (no .debug_info section)
if [ -f build/vcs_server ]; then
    if ! objdump -h build/vcs_server 2>/dev/null | grep -q "\.debug_info"; then
        check "Server binary stripped (no debug symbols)" "ok"
    else
        check "Server binary stripped (no debug symbols)" "debug symbols present — run: strip build/vcs_server"
    fi
fi

# 3. Log directory permissions
if [ -d logs ]; then
    PERM=$(stat -c "%a" logs)
    if [ "$PERM" = "700" ] || [ "$PERM" = "755" ]; then
        check "logs/ directory permissions ($PERM)" "ok"
    else
        check "logs/ directory permissions ($PERM)" "recommend 700: chmod 700 logs"
    fi
else
    check "logs/ directory exists" "not found — will be created on server start"
fi

# 4. No hardcoded passwords or tokens in source
if grep -rn "password\s*=\s*\"[^\"]\+\"" server/ client/ common/ 2>/dev/null \
   | grep -v "_hash\|placeholder\|your_password\|test\|empty\|comment" | grep -q .; then
    check "No hardcoded credentials in source" "found potential hardcoded values — review above"
else
    check "No hardcoded credentials in source" "ok"
fi

# 5. OpenSSL version
SSL_VER=$(openssl version 2>/dev/null | awk '{print $2}')
if [ -n "$SSL_VER" ]; then
    MAJOR=$(echo "$SSL_VER" | cut -d. -f1)
    MINOR=$(echo "$SSL_VER" | cut -d. -f2)
    if [ "$MAJOR" -gt 1 ] || ( [ "$MAJOR" -eq 1 ] && [ "$MINOR" -ge 1 ] ); then
        check "OpenSSL version >= 1.1.1 ($SSL_VER)" "ok"
    else
        check "OpenSSL version >= 1.1.1 ($SSL_VER)" "upgrade required"
    fi
else
    check "OpenSSL installed" "not found"
fi

# 6. SQLite3 available
if command -v sqlite3 >/dev/null 2>&1; then
    check "sqlite3 available" "ok"
else
    check "sqlite3 available" "not found — apt install sqlite3"
fi

# 7. Audit log chain integrity
if [ -f build/vcs_server ] && [ -f vcs_chat.db ]; then
    VERIFY=$(./build/vcs_server --verify-audit-log 2>&1)
    if echo "$VERIFY" | grep -q "PASS"; then
        check "Audit log chain integrity" "ok"
    else
        check "Audit log chain integrity" "$VERIFY"
    fi
else
    check "Audit log chain integrity" "skipped (no db yet)"
fi

# 8. ban_list.json valid JSON (if exists)
if [ -f ban_list.json ]; then
    if python3 -c "import json,sys; json.load(open('ban_list.json'))" 2>/dev/null; then
        check "ban_list.json is valid JSON" "ok"
    else
        check "ban_list.json is valid JSON" "invalid JSON — fix or delete"
    fi
else
    check "ban_list.json" "not found (ok if no bans)"
fi

# 9. valgrind check (quick)
if command -v valgrind >/dev/null 2>&1 && [ -f build/vcs_server ]; then
    check "valgrind available" "ok (run: valgrind --leak-check=full ./build/vcs_server)"
else
    check "valgrind available" "not installed — apt install valgrind"
fi

echo ""
echo "=== Result: $PASS passed, $FAIL failed ==="
echo ""
[ $FAIL -eq 0 ] && exit 0 || exit 1
