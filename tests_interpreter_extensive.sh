#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
KPP_PY="$ROOT/kpp.py"
KPP_BIN="$ROOT/dist/kpp"
TMP="/tmp/kpp_interpreter_extensive"

rm -rf "$TMP"
mkdir -p "$TMP"

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

run "baseline python runner" 0 python3 "$KPP_PY" "$ROOT/syntax.kpp"
contains "$TMP/out_1.txt" "Hello, world!"
contains "$TMP/out_1.txt" "Hello from C++ file"

if [ -x "$KPP_BIN" ]; then
  run "baseline binary runner" 0 "$KPP_BIN" "$ROOT/syntax.kpp"
  contains "$TMP/out_2.txt" "Hello, world!"
fi

cat > "$TMP/introspect.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
print('x')
\\\
print(type(p))
print(lang(p))
print(origin(p))
print(hash(p))
KPP
run "introspection helpers" 0 python3 "$KPP_PY" "$TMP/introspect.kpp"
contains "$TMP/out_3.txt" "script"
contains "$TMP/out_3.txt" "python"
contains "$TMP/out_3.txt" "inline"

cat > "$TMP/nonprint.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
print('x')
\\\
print(p)
KPP
run "artifact non-printability" 1 python3 "$KPP_PY" "$TMP/nonprint.kpp"
contains "$TMP/out_4.txt" "Script variables are executable artifacts and cannot be printed."

cat > "$TMP/emit.kpp" <<'KPP'
"prgm.start"
lib=define"c++"
\\\
// lib
int lib(){ return 1; }
\\\
app=define"c++" depends lib
\\\
// app
int main(){ return 0; }
\\\
emit.language "c++" app -> "/tmp/kpp_interpreter_extensive/main.cpp"
KPP
run "emit with dependencies" 0 python3 "$KPP_PY" "$TMP/emit.kpp"
test -f "$TMP/main.cpp"
test -f "$TMP/lib.cpp"

cat > "$TMP/sandbox_py.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import socket
print('no')
\\\
run.language "python" p sandboxed
KPP
run "sandbox python blocks network" 1 python3 "$KPP_PY" "$TMP/sandbox_py.kpp"
contains "$TMP/out_6.txt" "Sandbox blocked import of module \"socket\""

cat > "$TMP/deps_cycle.kpp" <<'KPP'
"prgm.start"
a=define"python"
\\\
print('a')
\\\
b=define"python" depends a
\\\
print('b')
\\\
a.dependencies.append(b)
run.language "python" b
KPP
run "dependency cycle detection" 1 python3 "$KPP_PY" "$TMP/deps_cycle.kpp"
contains "$TMP/out_7.txt" "Dependency cycle detected"

cat > "$TMP/sandbox_interp.kpp" <<'KPP'
"prgm.start"
js=define"javascript"
\\\
console.log('x')
\\\
run.language "javascript" js sandboxed
KPP
run "sandbox unsupported interpreted" 1 python3 "$KPP_PY" "$TMP/sandbox_interp.kpp"
contains "$TMP/out_8.txt" "Sandboxed execution is currently unavailable for interpreted language"

cat > "$TMP/cache.kpp" <<'KPP'
"prgm.start"
a=define"c"
\\\
#warning "cache-once"
#include <stdio.h>
int main(){ puts("ok"); return 0; }
\\\
run.language "c" a
run.language "c" a
KPP
run "compiled cache behavior" 0 python3 "$KPP_PY" "$TMP/cache.kpp"
contains "$TMP/out_9.txt" "ok"

echo ""
echo "Interpreter Extensive Summary: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
