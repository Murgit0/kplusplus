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
LAST_OUT=""

pass() {
  echo "PASS: $1"
  PASS=$((PASS + 1))
}

fail() {
  echo "FAIL: $1 :: $2"
  if [ -n "$LAST_OUT" ] && [ -f "$LAST_OUT" ]; then
    sed 's/^/    /' "$LAST_OUT"
  fi
  FAIL=$((FAIL + 1))
}

run_case() {
  local name="$1"
  local want_rc="$2"
  shift 2

  LAST_OUT="$TMP/out_$((PASS + FAIL + 1)).txt"
  set +e
  "$@" >"$LAST_OUT" 2>&1
  local rc=$?
  set -e

  if [ "$rc" -ne "$want_rc" ]; then
    fail "$name" "expected rc=$want_rc got rc=$rc"
    return 1
  fi
  return 0
}

expect_contains() {
  local text="$1"
  grep -Fq "$text" "$LAST_OUT"
}

# baseline
if run_case "baseline python runner" 0 python3 "$KPP_PY" "$ROOT/syntax.kpp" && expect_contains "Hello, world!" && expect_contains "Hello from C++ file"; then
  pass "baseline python runner"
else
  fail "baseline python runner" "unexpected output"
fi

if [ -x "$KPP_BIN" ]; then
  if run_case "baseline binary runner" 0 "$KPP_BIN" "$ROOT/syntax.kpp" && expect_contains "Hello, world!"; then
    pass "baseline binary runner"
  else
    fail "baseline binary runner" "unexpected output"
  fi
fi

# introspection
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
if run_case "introspection helpers" 0 python3 "$KPP_PY" "$TMP/introspect.kpp" && expect_contains "script" && expect_contains "python" && expect_contains "inline"; then
  pass "introspection helpers"
else
  fail "introspection helpers" "missing introspection output"
fi

# non-printability
cat > "$TMP/nonprint.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
print('x')
\\\
print(p)
KPP
if run_case "artifact non-printability" 1 python3 "$KPP_PY" "$TMP/nonprint.kpp" && expect_contains "Script variables are executable artifacts and cannot be printed."; then
  pass "artifact non-printability"
else
  fail "artifact non-printability" "non-printability broken"
fi

# emit
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
if run_case "emit with dependencies" 0 python3 "$KPP_PY" "$TMP/emit.kpp" && [ -f "$TMP/main.cpp" ] && [ -f "$TMP/lib.cpp" ]; then
  pass "emit with dependencies"
else
  fail "emit with dependencies" "emit output missing"
fi

# sandbox network block
cat > "$TMP/sandbox_py.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import socket
print('no')
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox python blocks network" 1 python3 "$KPP_PY" "$TMP/sandbox_py.kpp" && expect_contains "Sandbox blocked import of module \"socket\""; then
  pass "sandbox python blocks network"
else
  fail "sandbox python blocks network" "network not blocked"
fi

# dependency cycle
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
if run_case "dependency cycle detection" 1 python3 "$KPP_PY" "$TMP/deps_cycle.kpp" && expect_contains "Dependency cycle detected"; then
  pass "dependency cycle detection"
else
  fail "dependency cycle detection" "cycle not detected"
fi

# unsupported sandbox interpreted
cat > "$TMP/sandbox_interp.kpp" <<'KPP'
"prgm.start"
js=define"javascript"
\\\
console.log('x')
\\\
run.language "javascript" js sandboxed
KPP
if run_case "sandbox unsupported interpreted" 1 python3 "$KPP_PY" "$TMP/sandbox_interp.kpp" && expect_contains "Sandboxed execution is currently unavailable for interpreted language"; then
  pass "sandbox unsupported interpreted"
else
  fail "sandbox unsupported interpreted" "wrong error"
fi

# compiled cache
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
if run_case "compiled cache behavior" 0 python3 "$KPP_PY" "$TMP/cache.kpp" && expect_contains "ok"; then
  pass "compiled cache behavior"
else
  fail "compiled cache behavior" "cache behavior mismatch"
fi

# BUG 5 guard: relative run.file.language path resolves against script directory
mkdir -p "$TMP/bug5"
cat > "$TMP/bug5/hello.cpp" <<'CPP'
#include <iostream>
int main(){ std::cout << "bug5-ok" << std::endl; return 0; }
CPP
cat > "$TMP/bug5/script.kpp" <<'KPP'
"prgm.start"
run.file.language "c++" hello.cpp
KPP
if run_case "run.file.language resolves relative to script dir" 0 bash -lc "cd /tmp && python3 '$KPP_PY' '$TMP/bug5/script.kpp'" && expect_contains "bug5-ok"; then
  pass "run.file.language resolves relative to script dir"
else
  fail "run.file.language resolves relative to script dir" "relative path resolution broken"
fi

echo ""
echo "Interpreter Extensive Summary: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
