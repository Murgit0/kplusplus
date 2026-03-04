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
  if ! grep -Fq "$text" "$LAST_OUT"; then
    return 1
  fi
  return 0
}

expect_file_exists() {
  local path="$1"
  [ -f "$path" ]
}

expect_file_absent() {
  local path="$1"
  [ ! -f "$path" ]
}

# 1. Sandbox blocks network imports
cat > "$TMP/net_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import socket
print('x')
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks network" 1 python3 "$KPP_PY" "$TMP/net_block.kpp" && expect_contains 'Sandbox blocked import of module "socket"'; then
  pass "sandbox blocks network"
else
  fail "sandbox blocks network" "missing expected block"
fi

# 2. BUG 1 guard: os.system via indirect module usage is blocked
cat > "$TMP/os_system_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import pathlib
pathlib.os.system('echo SHOULD_NOT_RUN')
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks os.system escape" 1 python3 "$KPP_PY" "$TMP/os_system_block.kpp" && expect_contains 'Sandbox blocked os process execution.'; then
  pass "sandbox blocks os.system escape"
else
  fail "sandbox blocks os.system escape" "os.system escape not blocked"
fi

# 3. BUG 2 guard: ctypes is blocked
cat > "$TMP/ctypes_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import ctypes
ctypes.CDLL(None).system(b'echo SHOULD_NOT_RUN')
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks ctypes escape" 1 python3 "$KPP_PY" "$TMP/ctypes_block.kpp" && expect_contains 'Sandbox blocked import of module "ctypes"'; then
  pass "sandbox blocks ctypes escape"
else
  fail "sandbox blocks ctypes escape" "ctypes escape not blocked"
fi

# 4. BUG 3 guard: builtins import bypass blocked
cat > "$TMP/builtins_bypass.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import builtins
builtins.__import__('socket')
print('x')
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks builtins __import__ bypass" 1 python3 "$KPP_PY" "$TMP/builtins_bypass.kpp" && expect_contains 'Sandbox blocked import of module "builtins"'; then
  pass "sandbox blocks builtins __import__ bypass"
else
  fail "sandbox blocks builtins __import__ bypass" "builtins import bypass not blocked"
fi

cat > "$TMP/dunder_import_bypass.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
__import__('socket')
print('x')
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks direct __import__ bypass" 1 python3 "$KPP_PY" "$TMP/dunder_import_bypass.kpp" && expect_contains 'Sandbox blocked import of module "socket"'; then
  pass "sandbox blocks direct __import__ bypass"
else
  fail "sandbox blocks direct __import__ bypass" "direct __import__ bypass not blocked"
fi

# 5. BUG 4 guard: clean runtime error, no traceback leak
cat > "$TMP/no_traceback.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
exec("print('x')")
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox error does not leak traceback" 1 python3 "$KPP_PY" "$TMP/no_traceback.kpp" && expect_contains "Runtime error: name 'exec' is not defined" && ! grep -Fq "Traceback (most recent call last)" "$LAST_OUT"; then
  pass "sandbox error does not leak traceback"
else
  fail "sandbox error does not leak traceback" "traceback leaked or message missing"
fi

# 6. Sandbox denies fs by default
cat > "$TMP/fs_deny.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
open('/tmp/kpp_security_suite_repo/no.txt', 'w').write('x')
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox fs denied by default" 1 python3 "$KPP_PY" "$TMP/fs_deny.kpp" && expect_contains "Sandbox filesystem access denied"; then
  pass "sandbox fs denied by default"
else
  fail "sandbox fs denied by default" "missing fs denial"
fi

# 7. Allowlisted fs path works
cat > "$TMP/fs_allow.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
open('/tmp/kpp_security_suite_repo/allowed/ok.txt', 'w').write('ok')
print('ok')
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox fs allowlist" 0 env KPP_SANDBOX_ALLOW_PATHS=/tmp/kpp_security_suite_repo/allowed python3 "$KPP_PY" "$TMP/fs_allow.kpp" && expect_file_exists "$TMP/allowed/ok.txt"; then
  pass "sandbox fs allowlist"
else
  fail "sandbox fs allowlist" "allowlisted path write failed"
fi

# 8. Timeout enforcement
cat > "$TMP/timeout.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
while True:
    pass
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox timeout" 1 env KPP_SANDBOX_TIMEOUT=0.2 python3 "$KPP_PY" "$TMP/timeout.kpp" && expect_contains "Sandbox execution timed out"; then
  pass "sandbox timeout"
else
  fail "sandbox timeout" "timeout not enforced"
fi

# 9. Script non-printability remains enforced
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

# 10. Logging cannot bypass non-printability
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
if run_case "logging non-printability" 1 python3 "$KPP_PY" "$TMP/logging.kpp" && expect_contains "Script variables are executable artifacts and cannot be printed."; then
  pass "logging non-printability"
else
  fail "logging non-printability" "logging bypass"
fi

# 11. No shell injection via run.file.language path
cat > "$TMP/injection.kpp" <<'KPP'
"prgm.start"
run.file.language "python" "/tmp/nope.py;touch /tmp/kpp_security_repo_injected"
KPP
rm -f /tmp/kpp_security_repo_injected
if run_case "no shell injection via file path" 1 python3 "$KPP_PY" "$TMP/injection.kpp" && expect_file_absent /tmp/kpp_security_repo_injected; then
  pass "no shell injection via file path"
else
  fail "no shell injection via file path" "possible injection side effect"
fi

# 12. Binary parity checks
if [ -x "$KPP_BIN" ]; then
  if run_case "binary net block parity" 1 "$KPP_BIN" "$TMP/net_block.kpp" && expect_contains 'Sandbox blocked import of module "socket"'; then
    pass "binary net block parity"
  else
    fail "binary net block parity" "binary sandbox mismatch"
  fi

  if run_case "binary non-printability parity" 1 "$KPP_BIN" "$TMP/nonprint.kpp" && expect_contains "Script variables are executable artifacts and cannot be printed."; then
    pass "binary non-printability parity"
  else
    fail "binary non-printability parity" "binary non-printability mismatch"
  fi
fi

# 13. KPP-005 guard: run.language rejects string literals (must be ScriptArtifact)
cat > "$TMP/run_language_string_reject.kpp" <<'KPP'
"prgm.start"
run.language "python" "print('unsafe')"
KPP
if run_case "run.language rejects string expressions" 1 python3 "$KPP_PY" "$TMP/run_language_string_reject.kpp" && expect_contains "run.language expects a script variable created with define"; then
  pass "run.language rejects string expressions"
else
  fail "run.language rejects string expressions" "string execution not rejected"
fi

# 14. KPP-006 guard: compiled sandbox cannot silently run unsandboxed
cat > "$TMP/compiled_sandbox_enforced.kpp" <<'KPP'
"prgm.start"
p=define"c"
\\\
#include <stdlib.h>
int main(){ return system("touch /tmp/kpp_security_compiled_sandbox_touch"); }
\\\
run.language "c" p sandboxed
KPP
rm -f /tmp/kpp_security_compiled_sandbox_touch
if run_case "compiled sandbox not silently ignored" 1 python3 "$KPP_PY" "$TMP/compiled_sandbox_enforced.kpp" && expect_file_absent /tmp/kpp_security_compiled_sandbox_touch; then
  pass "compiled sandbox not silently ignored"
else
  fail "compiled sandbox not silently ignored" "compiled sandbox fell back or side effect occurred"
fi

# 15. KPP-007 guard: emit blocks symlink targets
echo "SAFE" > "$TMP/emit_real.txt"
ln -sf "$TMP/emit_real.txt" "$TMP/emit_link.py"
cat > "$TMP/emit_symlink_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
print('x')
\\\
emit.language "python" p -> "/tmp/kpp_security_suite_repo/emit_link.py"
KPP
if run_case "emit blocks symlink path" 1 python3 "$KPP_PY" "$TMP/emit_symlink_block.kpp" && expect_contains "must not traverse symlinks" && grep -Fq "SAFE" "$TMP/emit_real.txt"; then
  pass "emit blocks symlink path"
else
  fail "emit blocks symlink path" "symlink safety failed"
fi

# 16. KPP-008 guard: emit blocks relative traversal outside script dir
cat > "$TMP/emit_traversal_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
print('x')
\\\
emit.language "python" p -> "../escape.py"
KPP
if run_case "emit blocks relative traversal" 1 python3 "$KPP_PY" "$TMP/emit_traversal_block.kpp" && expect_contains "escapes script directory"; then
  pass "emit blocks relative traversal"
else
  fail "emit blocks relative traversal" "relative traversal not blocked"
fi

# 17. KPP-009 guard: emit blocks stdout/proc-like special paths
cat > "$TMP/emit_devstdout_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
print('x')
\\\
emit.language "python" p -> "/dev/stdout"
KPP
if run_case "emit blocks /dev/stdout" 1 python3 "$KPP_PY" "$TMP/emit_devstdout_block.kpp" && (expect_contains "must not traverse symlinks" || expect_contains "not allowed"); then
  pass "emit blocks /dev/stdout"
else
  fail "emit blocks /dev/stdout" "special path not blocked"
fi

# 18. KPP-010 guard: ScriptArtifact source cannot be read via object.__getattribute__
cat > "$TMP/source_attr_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
print('x')
\\\
print(object.__getattribute__(p, "source"))
KPP
if run_case "artifact source opaque" 1 python3 "$KPP_PY" "$TMP/source_attr_block.kpp" && expect_contains "has no attribute 'source'"; then
  pass "artifact source opaque"
else
  fail "artifact source opaque" "source attribute leaked"
fi

# 19. KPP-011 guard: ScriptArtifact cannot be pickled
cat > "$TMP/pickle_block.kpp" <<'KPP'
"prgm.start"
import pickle
p=define"python"
\\\
print('x')
\\\
pickle.dumps(p)
KPP
if run_case "artifact pickle blocked" 1 python3 "$KPP_PY" "$TMP/pickle_block.kpp" && expect_contains "cannot be serialized"; then
  pass "artifact pickle blocked"
else
  fail "artifact pickle blocked" "pickle serialization allowed"
fi

# 20. KPP-012 guard: compiled cache poisoning detected
cat > "$TMP/cache_poison.kpp" <<'KPP'
"prgm.start"
p=define"c"
\\\
#include <stdio.h>
int main(){ puts("cache-ok"); return 0; }
\\\
run.language "c" p
KPP
CACHE_HOME="$TMP/cache_home"
rm -rf "$CACHE_HOME"
if run_case "cache poison seed compile" 0 env XDG_CACHE_HOME="$CACHE_HOME" python3 "$KPP_PY" "$TMP/cache_poison.kpp"; then
  BIN_PATH="$(find "$CACHE_HOME/kpp/compiled_cache" -type f -name program | head -n 1)"
  if [ -n "${BIN_PATH:-}" ]; then
    echo 'tampered' > "$BIN_PATH"
    chmod +x "$BIN_PATH"
    if run_case "cache poison detection" 1 env XDG_CACHE_HOME="$CACHE_HOME" python3 "$KPP_PY" "$TMP/cache_poison.kpp" && expect_contains "integrity check failed"; then
      pass "cache poison detection"
    else
      fail "cache poison detection" "tampered cache binary was not detected"
    fi
  else
    fail "cache poison detection" "could not locate cached binary"
  fi
else
  fail "cache poison seed compile" "failed to seed compiled cache"
fi

# 21. KPP-014 guard: emit does not overwrite existing files
echo "KEEP" > "$TMP/emit_existing.py"
cat > "$TMP/emit_overwrite_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
print('x')
\\\
emit.language "python" p -> "/tmp/kpp_security_suite_repo/emit_existing.py"
KPP
if run_case "emit blocks overwrite" 1 python3 "$KPP_PY" "$TMP/emit_overwrite_block.kpp" && expect_contains "already exists" && grep -Fq "KEEP" "$TMP/emit_existing.py"; then
  pass "emit blocks overwrite"
else
  fail "emit blocks overwrite" "overwrite protection failed"
fi

# 22. KPP-015 guard: emit deep path works and is not silent-fail
rm -rf "$TMP/deep"
cat > "$TMP/emit_deep_path.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
print('x')
\\\
emit.language "python" p -> "/tmp/kpp_security_suite_repo/deep/a/b/out.py"
KPP
if run_case "emit deep path creation" 0 python3 "$KPP_PY" "$TMP/emit_deep_path.kpp" && expect_file_exists "$TMP/deep/a/b/out.py"; then
  pass "emit deep path creation"
else
  fail "emit deep path creation" "deep path emit failed"
fi

# 23. KPP-016 guard: multiple depends clauses parse correctly
cat > "$TMP/multiple_depends.kpp" <<'KPP'
"prgm.start"
left=define"python"
\\\
print('left')
\\\
right=define"python"
\\\
print('right')
\\\
top=define"python" depends left depends right
\\\
print('top')
\\\
run.language "python" top
KPP
if run_case "multiple depends parsing" 0 python3 "$KPP_PY" "$TMP/multiple_depends.kpp" && expect_contains "top"; then
  pass "multiple depends parsing"
else
  fail "multiple depends parsing" "depends parser regression"
fi

# 24. KPP-017 guard: reserved runtime names cannot be clobbered
cat > "$TMP/reserved_name_block.kpp" <<'KPP'
"prgm.start"
kpp = "oops"
KPP
if run_case "reserved name clobber blocked" 1 python3 "$KPP_PY" "$TMP/reserved_name_block.kpp" && expect_contains "reserved K++ runtime name"; then
  pass "reserved name clobber blocked"
else
  fail "reserved name clobber blocked" "reserved names are writable"
fi

# 25. KPP-019 guard: undefined variable errors do not leak traceback
cat > "$TMP/no_traceback_runtime.kpp" <<'KPP'
"prgm.start"
run.language "python" undefined_var
KPP
if run_case "runtime errors suppress raw traceback" 1 python3 "$KPP_PY" "$TMP/no_traceback_runtime.kpp" && expect_contains "Runtime error: name 'undefined_var' is not defined" && ! grep -Fq "Traceback (most recent call last)" "$LAST_OUT"; then
  pass "runtime errors suppress raw traceback"
else
  fail "runtime errors suppress raw traceback" "traceback leaked"
fi

# 26. KPP-020 guard: sandbox memory limit enforced
cat > "$TMP/memory_limit.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
s = "x" * (256 * 1024 * 1024)
print(len(s))
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox memory limit" 1 env KPP_SANDBOX_MEMORY_MB=32 python3 "$KPP_PY" "$TMP/memory_limit.kpp" && expect_contains "MemoryError"; then
  pass "sandbox memory limit"
else
  fail "sandbox memory limit" "memory cap not enforced"
fi

# 27. KPP-013 guard: sandbox module state does not leak between runs
cat > "$TMP/state_isolation.kpp" <<'KPP'
"prgm.start"
a=define"python"
\\\
import decimal
decimal.kpp_secret='TOKEN'
\\\
b=define"python"
\\\
import decimal
try:
    print(decimal.kpp_secret)
except Exception:
    print("MISSING")
\\\
run.language "python" a sandboxed
run.language "python" b sandboxed
KPP
if run_case "sandbox state isolation" 0 python3 "$KPP_PY" "$TMP/state_isolation.kpp" && expect_contains "MISSING"; then
  pass "sandbox state isolation"
else
  fail "sandbox state isolation" "state leaked between sandbox runs"
fi

# 28. KPP-021 guard: importlib.import_module escape blocked
cat > "$TMP/importlib_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import importlib
importlib.import_module("os")
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks importlib import_module escape" 1 python3 "$KPP_PY" "$TMP/importlib_block.kpp" && expect_contains 'Sandbox blocked import of module "importlib"'; then
  pass "sandbox blocks importlib import_module escape"
else
  fail "sandbox blocks importlib import_module escape" "importlib escape was not blocked"
fi

# 29. KPP-022 guard: os.fork via indirect os reference is blocked
cat > "$TMP/fork_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import pathlib
pathlib.os.fork()
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks os.fork escape" 1 python3 "$KPP_PY" "$TMP/fork_block.kpp" && expect_contains "Sandbox blocked os process execution."; then
  pass "sandbox blocks os.fork escape"
else
  fail "sandbox blocks os.fork escape" "os.fork escape was not blocked"
fi

# 30. KPP-023 guard: signal handler injection path is blocked
cat > "$TMP/signal_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import signal
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks signal import" 1 python3 "$KPP_PY" "$TMP/signal_block.kpp" && expect_contains 'Sandbox blocked import of module "signal"'; then
  pass "sandbox blocks signal import"
else
  fail "sandbox blocks signal import" "signal module import was not blocked"
fi

# 31. KPP-024 guard: multiprocessing escape blocked
cat > "$TMP/multiprocessing_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import multiprocessing
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks multiprocessing import" 1 python3 "$KPP_PY" "$TMP/multiprocessing_block.kpp" && expect_contains 'Sandbox blocked import of module "multiprocessing"'; then
  pass "sandbox blocks multiprocessing import"
else
  fail "sandbox blocks multiprocessing import" "multiprocessing import was not blocked"
fi

# 32. KPP-025 guard: _thread escape blocked
cat > "$TMP/thread_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import _thread
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks _thread import" 1 python3 "$KPP_PY" "$TMP/thread_block.kpp" && expect_contains 'Sandbox blocked import of module "_thread"'; then
  pass "sandbox blocks _thread import"
else
  fail "sandbox blocks _thread import" "_thread import was not blocked"
fi

# 33. KPP-026/027 guard: ScriptArtifact equality/hash and dict-key usability
cat > "$TMP/artifact_equality_hash.kpp" <<'KPP'
"prgm.start"
a=define"python"
\\\
print('same')
\\\
b=define"python"
\\\
print('same')
\\\
meta={}
meta[a]="ok"
print(a == b)
print(meta[b])
print(len({a, b}))
KPP
if run_case "artifact equality and hashability" 0 python3 "$KPP_PY" "$TMP/artifact_equality_hash.kpp" && expect_contains "True" && expect_contains "ok" && expect_contains "1"; then
  pass "artifact equality and hashability"
else
  fail "artifact equality and hashability" "artifacts are not content-comparable/hashable"
fi

# 34. KPP-028 guard: /tmp enumeration blocked without allowlist
cat > "$TMP/tmp_enum_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import pathlib
print(len(list(pathlib.Path('/tmp').iterdir())))
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks tmp enumeration" 1 python3 "$KPP_PY" "$TMP/tmp_enum_block.kpp" && (expect_contains "Sandbox denied filesystem access" || expect_contains "Sandbox filesystem access denied"); then
  pass "sandbox blocks tmp enumeration"
else
  fail "sandbox blocks tmp enumeration" "tmp enumeration was not blocked"
fi

# 35. KPP-029 guard: run.file.language directory path returns clean runtime error
cat > "$TMP/run_file_dir_error.kpp" <<'KPP'
"prgm.start"
run.file.language "python" "/tmp"
KPP
if run_case "run.file.language directory error is clean" 1 python3 "$KPP_PY" "$TMP/run_file_dir_error.kpp" && expect_contains "Path is a directory for run.file.language"; then
  pass "run.file.language directory error is clean"
else
  fail "run.file.language directory error is clean" "directory handling error is unclear"
fi

# 36. KPP-030 guard: very deep dependency chains fail with explicit limit error
cat > "$TMP/dependency_depth_limit.kpp" <<'KPP'
"prgm.start"
nodes=[]
for i in range(500):
    node = __kpp_define("python", "print('x')\n", f"n{i}", [])
    if nodes:
        node.dependencies.append(nodes[-1])
    nodes.append(node)
run.language "python" nodes[-1]
KPP
if run_case "dependency depth guard" 1 python3 "$KPP_PY" "$TMP/dependency_depth_limit.kpp" && expect_contains "Dependency chain exceeds maximum depth"; then
  pass "dependency depth guard"
else
  fail "dependency depth guard" "deep dependency graph did not fail safely"
fi

# 37. KPP-031 guard: null byte in language name is rejected clearly
NULL_LANG_FILE="$TMP/null_lang_name.kpp"
python3 - "$NULL_LANG_FILE" <<'PY'
import pathlib
import sys

target = pathlib.Path(sys.argv[1])
target.write_bytes(
    b'"prgm.start"\n'
    b'p=define"py\x00thon"\n'
    b'\\\\\\\n'
    b'print("x")\n'
    b'\\\\\\\n'
    b'run.language "python" p\n'
)
PY
if run_case "null-byte language rejected" 1 python3 "$KPP_PY" "$NULL_LANG_FILE" && expect_contains "Invalid language name"; then
  pass "null-byte language rejected"
else
  fail "null-byte language rejected" "null-byte language name was accepted"
fi

# 38. KPP-032 guard: atexit registration blocked in sandbox
cat > "$TMP/atexit_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import atexit
atexit.register(print, "x")
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks atexit registration path" 1 python3 "$KPP_PY" "$TMP/atexit_block.kpp" && expect_contains 'Sandbox blocked import of module "atexit"'; then
  pass "sandbox blocks atexit registration path"
else
  fail "sandbox blocks atexit registration path" "atexit registration remained available"
fi

# 39. KPP-033 guard: shutil import/copy/move vectors blocked
cat > "$TMP/shutil_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import shutil
shutil.copy("/etc/passwd", "/tmp/kpp_security_suite_repo/shutil_copy.txt")
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks shutil file operations" 1 python3 "$KPP_PY" "$TMP/shutil_block.kpp" && expect_contains 'Sandbox blocked import of module "shutil"'; then
  pass "sandbox blocks shutil file operations"
else
  fail "sandbox blocks shutil file operations" "shutil operations remained available"
fi

# 40. KPP-034 guard: io.open/io.FileIO bypass blocked
cat > "$TMP/io_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import io
io.open("/etc/passwd", "r").read()
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks io.open/FileIO import path" 1 python3 "$KPP_PY" "$TMP/io_block.kpp" && expect_contains 'Sandbox blocked import of module "io"'; then
  pass "sandbox blocks io.open/FileIO import path"
else
  fail "sandbox blocks io.open/FileIO import path" "io bypass remained available"
fi

# 41. KPP-035 guard: pathlib read/write respects sandbox path guard
cat > "$TMP/pathlib_file_guard.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import pathlib
print(pathlib.Path("/etc/passwd").read_text())
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks pathlib file read outside allowlist" 1 python3 "$KPP_PY" "$TMP/pathlib_file_guard.kpp" && (expect_contains "Sandbox denied filesystem access" || expect_contains "Sandbox filesystem access denied"); then
  pass "sandbox blocks pathlib file read outside allowlist"
else
  fail "sandbox blocks pathlib file read outside allowlist" "pathlib file guard bypassed"
fi

# 42. KPP-036 guard: tempfile creation blocked
cat > "$TMP/tempfile_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import tempfile
tempfile.NamedTemporaryFile(delete=False)
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks tempfile creation" 1 python3 "$KPP_PY" "$TMP/tempfile_block.kpp" && expect_contains 'Sandbox blocked import of module "tempfile"'; then
  pass "sandbox blocks tempfile creation"
else
  fail "sandbox blocks tempfile creation" "tempfile remained available"
fi

# 43. KPP-037 guard: linecache arbitrary read blocked
cat > "$TMP/linecache_block.kpp" <<'KPP'
"prgm.start"
p=define"python"
\\\
import linecache
print(linecache.getline("/etc/passwd", 1))
\\\
run.language "python" p sandboxed
KPP
if run_case "sandbox blocks linecache import path" 1 python3 "$KPP_PY" "$TMP/linecache_block.kpp" && expect_contains 'Sandbox blocked import of module "linecache"'; then
  pass "sandbox blocks linecache import path"
else
  fail "sandbox blocks linecache import path" "linecache read remained available"
fi

# 44. allow.all top-of-doc directive bypasses sandbox hardening
cat > "$TMP/allow_all_bypass.kpp" <<'KPP'
"allow.all"
"prgm.start"
p=define"python"
\\\
import socket
open("/tmp/kpp_security_suite_repo/allow_all.txt", "w").write(socket.gethostname())
\\\
run.language "python" p sandboxed
KPP
rm -f "$TMP/allow_all.txt"
if run_case "allow.all bypasses sandbox hardening" 0 python3 "$KPP_PY" "$TMP/allow_all_bypass.kpp" && expect_file_exists "$TMP/allow_all.txt"; then
  pass "allow.all bypasses sandbox hardening"
else
  fail "allow.all bypasses sandbox hardening" "allow.all did not disable sandbox restrictions"
fi

echo ""
echo "Security Summary: PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
