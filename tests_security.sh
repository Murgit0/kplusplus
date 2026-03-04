#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
KPP_PY="$ROOT/kpp.py"
KPP_BIN="$ROOT/dist/kpp"
TMP="/tmp/kpp_security_suite_repo"

rm -rf "$TMP"
mkdir -p "$TMP/allowed" "$TMP/other"

PASS=0
FAIL=0

run() {
  local name="$1"
  local want_rc="$2"
  shift 2
  local out="$TMP/out_$((PASS+FAIL+1)).txt"
  set +e
  "$@" >"$out" 2>&1
  local rc=$?
  set -e
  if [ "$rc" -ne "$want_rc" ]; then
    echo "FAIL: $name (rc=$rc want=$want_rc)"
    sed 's/^/    /' "$out"
    FAIL=$((FAIL+1))
    return
  fi
  echo "PASS: $name"
  PASS=$((PASS+1))
}

contains() {
  local file="$1"
  local text="$2"
  grep -Fq "$text" "$file"
}

cat > "$TMP/net_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import socket
print('x')
\\\
run.language "python" p sandboxed
KPP
run "sandbox blocks network" 1 python3 "$KPP_PY" "$TMP/net_block.kpp"
contains "$TMP/out_1.txt" "Sandbox blocked import of module \"socket\""

cat > "$TMP/fs_deny.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
open('/tmp/kpp_security_suite_repo/no.txt', 'w').write('x')
\\\
run.language "python" p sandboxed
KPP
run "sandbox fs denied by default" 1 python3 "$KPP_PY" "$TMP/fs_deny.kpp"
contains "$TMP/out_2.txt" "Sandbox filesystem access denied"

cat > "$TMP/fs_allow.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
open('/tmp/kpp_security_suite_repo/allowed/ok.txt', 'w').write('ok')
print('ok')
\\\
run.language "python" p sandboxed
KPP
run "sandbox fs allowlist" 0 env KPP_SANDBOX_ALLOW_PATHS=/tmp/kpp_security_suite_repo/allowed python3 "$KPP_PY" "$TMP/fs_allow.kpp"
test -f "$TMP/allowed/ok.txt"

cat > "$TMP/timeout.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
while True:
    pass
\\\
run.language "python" p sandboxed
KPP
run "sandbox timeout" 1 env KPP_SANDBOX_TIMEOUT=0.2 python3 "$KPP_PY" "$TMP/timeout.kpp"
contains "$TMP/out_4.txt" "Sandbox execution timed out"

cat > "$TMP/nonprint.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
print('x')
\\\
print(p)
KPP
run "artifact non-printability" 1 python3 "$KPP_PY" "$TMP/nonprint.kpp"
contains "$TMP/out_5.txt" "Script variables are executable artifacts and cannot be printed."

cat > "$TMP/logging.kpp" <<'KPP'
"prgm.start"
import logging
logging.basicConfig(level=logging.INFO)
p=define"python"
\\\
print('x')
\\\
logging.info(p)
KPP
run "logging non-printability" 1 python3 "$KPP_PY" "$TMP/logging.kpp"
contains "$TMP/out_6.txt" "Script variables are executable artifacts and cannot be printed."

cat > "$TMP/injection.kpp" <<'KPP'
"prgm.start"
run.file.language "python" "/tmp/nope.py;touch /tmp/kpp_security_repo_injected"
KPP
rm -f /tmp/kpp_security_repo_injected
run "no shell injection via file path" 1 python3 "$KPP_PY" "$TMP/injection.kpp"
[ ! -f /tmp/kpp_security_repo_injected ]

if [ -x "$KPP_BIN" ]; then
  run "binary net block parity" 1 "$KPP_BIN" "$TMP/net_block.kpp"
  contains "$TMP/out_8.txt" "Sandbox blocked import of module \"socket\""

  run "binary non-printability parity" 1 "$KPP_BIN" "$TMP/nonprint.kpp"
  contains "$TMP/out_9.txt" "Script variables are executable artifacts and cannot be printed."
fi

echo ""
echo "Security Summary: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
