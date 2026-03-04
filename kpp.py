#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import builtins
import hashlib
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import traceback
from dataclasses import dataclass, field


PROGRAM_START = '"prgm.start"'
BLOCK_DELIMITER = "\\\\\\"
DEFINE_RE = re.compile(r'^(\s*)([A-Za-z_]\w*)\s*=\s*define"([^"]+)"(?:\s+depends\s+(.+?))?\s*$')
RUN_LANGUAGE_RE = re.compile(r'^(\s*)run\.language\s+"([^"]+)"\s+(.+?)\s*$')
RUN_FILE_LANGUAGE_RE = re.compile(r'^(\s*)run\.file\.language\s+"([^"]+)"\s+(.+?)\s*$')
EMIT_LANGUAGE_RE = re.compile(r'^(\s*)emit\.language\s+"([^"]+)"\s+(.+?)\s*->\s*(.+?)\s*$')

LANGUAGE_EXTENSIONS = {
    "python": "py",
    "python3": "py",
    "py": "py",
    "bash": "sh",
    "sh": "sh",
    "shell": "sh",
    "javascript": "js",
    "js": "js",
    "node": "js",
    "typescript": "ts",
    "ts": "ts",
    "ruby": "rb",
    "rb": "rb",
    "php": "php",
    "perl": "pl",
    "lua": "lua",
    "r": "r",
    "swift": "swift",
    "rust": "rs",
    "rs": "rs",
    "c++": "cpp",
    "cpp": "cpp",
    "cxx": "cpp",
    "c": "c",
    "go": "go",
    "html": "html",
    "htm": "html",
    "css": "css",
}

LANGUAGE_COMMAND_ALIASES = {
    "python": "python3",
    "python3": "python3",
    "py": "python3",
    "javascript": "node",
    "js": "node",
    "node": "node",
    "bash": "bash",
    "sh": "bash",
    "shell": "bash",
    "r": "Rscript",
}

COMPILED_LANGUAGE_SPECS = {
    "c": {
        "aliases": ("c",),
        "suffix": ".c",
        "compile_template": ("gcc", "{src}", "-O2", "-o", "{out}"),
    },
    "cpp": {
        "aliases": ("c++", "cpp", "cxx"),
        "suffix": ".cpp",
        "compile_template": ("g++", "{src}", "-std=c++17", "-O2", "-o", "{out}"),
    },
    "rust": {
        "aliases": ("rust", "rs"),
        "suffix": ".rs",
        "compile_template": ("rustc", "{src}", "-O", "-o", "{out}"),
    },
    "go": {
        "aliases": ("go",),
        "suffix": ".go",
        "compile_template": ("go", "build", "-o", "{out}", "{src}"),
    },
}
COMPILED_ALIAS_TO_FAMILY: dict[str, str] = {}
for _family_name, _spec in COMPILED_LANGUAGE_SPECS.items():
    for _alias in _spec["aliases"]:
        COMPILED_ALIAS_TO_FAMILY[_alias] = _family_name

SCRIPT_ARTIFACT_PRINT_ERROR = "Script variables are executable artifacts and cannot be printed."


@dataclass
class ScriptArtifact:
    language: str
    source: str
    origin: str
    name: str | None = None
    source_path: str | None = None
    dependencies: list["ScriptArtifact"] = field(default_factory=list)
    hash: str = field(init=False)

    def __post_init__(self) -> None:
        if self.origin not in ("inline", "file"):
            raise RuntimeError(f'Invalid script artifact origin "{self.origin}"')
        self.dependencies = list(self.dependencies)
        self.hash = _artifact_content_hash(self.language, self.source, self.origin)

    def _raise_non_printable(self) -> None:
        raise RuntimeError(SCRIPT_ARTIFACT_PRINT_ERROR)

    def __str__(self) -> str:
        self._raise_non_printable()

    def __repr__(self) -> str:
        self._raise_non_printable()

    def __format__(self, format_spec: str) -> str:
        self._raise_non_printable()

    def __add__(self, other: object) -> object:
        self._raise_non_printable()

    def __radd__(self, other: object) -> object:
        self._raise_non_printable()


@dataclass(frozen=True)
class LanguageInfo:
    name: str
    kind: str
    available: bool
    compiler: str | None = None
    interpreter: str | None = None


@dataclass(frozen=True)
class SandboxOptions:
    allow_paths: tuple[pathlib.Path, ...]
    timeout_seconds: float | None
    env: dict[str, str]


class KppRuntimeAPI:
    def languages(self) -> list[str]:
        aliases: set[str] = set()
        aliases.update(("python", "python3", "py"))
        aliases.update(("html", "htm", "css"))
        aliases.update(COMPILED_ALIAS_TO_FAMILY.keys())
        aliases.update(LANGUAGE_COMMAND_ALIASES.keys())
        aliases.update(LANGUAGE_EXTENSIONS.keys())
        return sorted(aliases)

    def language(self, name: str) -> LanguageInfo:
        lang = _normalized_language(name)
        if lang in ("python", "python3", "py"):
            return LanguageInfo(name=lang, kind="native", available=True, interpreter=sys.executable)

        if lang in ("html", "htm", "css"):
            browser_cmd = _browser_launcher_binary()
            return LanguageInfo(
                name=lang,
                kind="artifact",
                available=browser_cmd is not None,
                interpreter=browser_cmd,
            )

        compiled_family = _compiled_language_family(lang)
        if compiled_family is not None:
            compiler = str(COMPILED_LANGUAGE_SPECS[compiled_family]["compile_template"][0])
            return LanguageInfo(
                name=lang,
                kind="compiled",
                available=shutil.which(compiler) is not None,
                compiler=compiler,
            )

        runtime = _runtime_command_for_capabilities(lang)
        return LanguageInfo(
            name=lang,
            kind="interpreted",
            available=runtime is not None and shutil.which(runtime) is not None,
            interpreter=runtime,
        )


class KppSyntaxError(Exception):
    pass


def _normalized_language(name: str) -> str:
    return name.strip().lower().replace(" ", "")


def _artifact_content_hash(language: str, source: str, origin: str) -> str:
    hasher = hashlib.sha256()
    hasher.update(_normalized_language(language).encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(origin.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(source.encode("utf-8"))
    return hasher.hexdigest()


def _runtime_command_for_capabilities(language: str) -> str | None:
    if language in COMPILED_ALIAS_TO_FAMILY:
        return None
    if language in LANGUAGE_COMMAND_ALIASES:
        return LANGUAGE_COMMAND_ALIASES[language]
    if not language or any(ch.isspace() for ch in language):
        return None
    return language


def _language_extension(language: str) -> str:
    lang = _normalized_language(language)
    if lang in LANGUAGE_EXTENSIONS:
        return LANGUAGE_EXTENSIONS[lang]
    cleaned = "".join(ch for ch in lang if ch.isalnum())
    return cleaned or "txt"


def _runtime_command(language: str) -> str:
    lang = _normalized_language(language)
    if lang in COMPILED_ALIAS_TO_FAMILY:
        raise RuntimeError(
            f'Compiled language "{language}" must be compiled to a binary, not run as interpreted code.'
        )
    runtime = _runtime_command_for_capabilities(lang)
    if runtime is None:
        raise RuntimeError(
            f'Cannot infer runtime command for language "{language}". Use a single-word runtime name.'
        )
    return runtime


def _is_web_artifact_language(language: str) -> bool:
    return language in ("html", "htm", "css")


def _compiled_language_family(language: str) -> str | None:
    return COMPILED_ALIAS_TO_FAMILY.get(language)


def _compiled_binary_filename() -> str:
    return "program.exe" if os.name == "nt" else "program"


def _compiled_cache_root() -> pathlib.Path:
    root = pathlib.Path(tempfile.gettempdir()) / "kpp_compiled_cache"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _compiled_cache_key(family: str, source_code: str, extra_material: str = "") -> str:
    spec = COMPILED_LANGUAGE_SPECS[family]
    hasher = hashlib.sha256()
    hasher.update(family.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(" ".join(spec["compile_template"]).encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(sys.platform.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(source_code.encode("utf-8"))
    if extra_material:
        hasher.update(b"\0")
        hasher.update(extra_material.encode("utf-8"))
    return hasher.hexdigest()


def _compiled_command(
    family: str,
    source_path: pathlib.Path,
    output_path: pathlib.Path,
    source_dir_hint: pathlib.Path | None = None,
) -> list[str]:
    template = list(COMPILED_LANGUAGE_SPECS[family]["compile_template"])
    command = [part.format(src=str(source_path), out=str(output_path)) for part in template]

    # Preserve common local-include behavior when compiling copied sources.
    if family in ("c", "cpp") and source_dir_hint is not None:
        command.insert(1, f"-I{source_dir_hint}")

    return command


def _write_temp_compile_source(source_code: str, suffix: str) -> pathlib.Path:
    source_dir = pathlib.Path(tempfile.gettempdir()) / "kpp_compile_sources"
    source_dir.mkdir(parents=True, exist_ok=True)
    fd, path_value = tempfile.mkstemp(
        prefix="kpp_src_",
        suffix=suffix,
        dir=str(source_dir),
        text=True,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(source_code)
    return pathlib.Path(path_value)


def _compile_inline_with_cache(
    family: str,
    source_code: str,
    base_dir: pathlib.Path,
    dry_run: bool,
    extra_material: str = "",
) -> pathlib.Path:
    key = _compiled_cache_key(family, source_code, extra_material=f"inline:{base_dir}:{extra_material}")
    cache_dir = _compiled_cache_root() / family / key
    output_path = cache_dir / _compiled_binary_filename()
    if output_path.exists():
        return output_path

    cache_dir.mkdir(parents=True, exist_ok=True)
    suffix = COMPILED_LANGUAGE_SPECS[family]["suffix"]
    temp_source_path = _write_temp_compile_source(source_code, suffix)
    try:
        command = _compiled_command(
            family=family,
            source_path=temp_source_path,
            output_path=output_path,
            source_dir_hint=base_dir,
        )
        _run_command(command, cwd=base_dir, dry_run=dry_run)
    finally:
        if temp_source_path.exists():
            temp_source_path.unlink()

    return output_path


def _compile_file_with_cache(
    family: str,
    source_path: pathlib.Path,
    source_code: str,
    base_dir: pathlib.Path,
    dry_run: bool,
    extra_material: str = "",
) -> pathlib.Path:
    key = _compiled_cache_key(
        family,
        source_code,
        extra_material=f"file:{source_path.resolve()}:{extra_material}",
    )
    cache_dir = _compiled_cache_root() / family / key
    output_path = cache_dir / _compiled_binary_filename()
    if output_path.exists():
        return output_path

    cache_dir.mkdir(parents=True, exist_ok=True)
    command = _compiled_command(
        family=family,
        source_path=source_path,
        output_path=output_path,
        source_dir_hint=source_path.parent,
    )
    _run_command(command, cwd=base_dir, dry_run=dry_run)
    return output_path


def _artifact_suffix(language: str) -> str:
    if language in ("html", "htm"):
        return ".html"
    if language == "css":
        return ".css"
    return ".txt"


def _browser_launcher_binary() -> str | None:
    if os.name == "nt":
        return "cmd" if shutil.which("cmd") else None
    if sys.platform == "darwin":
        return "open" if shutil.which("open") else None
    return "xdg-open" if shutil.which("xdg-open") else None


def _browser_open_command(target: pathlib.Path) -> list[str]:
    launcher = _browser_launcher_binary()
    if launcher is None:
        raise RuntimeError("No browser launcher available for artifact rendering on this system.")

    if os.name == "nt":
        # "start" is a shell built-in, so it must run via cmd.exe.
        return [launcher, "/c", "start", "", str(target)]
    return [launcher, str(target)]


def _write_temp_artifact(content: str, suffix: str) -> pathlib.Path:
    artifact_dir = pathlib.Path(tempfile.gettempdir()) / "kpp_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    fd, path_value = tempfile.mkstemp(prefix="kpp_", suffix=suffix, dir=str(artifact_dir), text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    return pathlib.Path(path_value)


def _open_in_browser(target: pathlib.Path, cwd: pathlib.Path, dry_run: bool) -> None:
    _run_command(_browser_open_command(target), cwd=cwd, dry_run=dry_run)


def _run_command(
    command: list[str],
    cwd: pathlib.Path,
    dry_run: bool,
    env: dict[str, str] | None = None,
    timeout_seconds: float | None = None,
) -> None:
    if dry_run:
        print("$", " ".join(command))
        return

    try:
        subprocess.run(
            command,
            cwd=str(cwd),
            check=True,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
            env=env,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Missing required tool: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Command timed out after {timeout_seconds} seconds: {' '.join(command)}") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Command failed with exit code {exc.returncode}: {' '.join(command)}") from exc


def _load_sandbox_options(base_dir: pathlib.Path) -> SandboxOptions:
    allowlist_raw = os.environ.get("KPP_SANDBOX_ALLOW_PATHS", "").strip()
    allow_paths: list[pathlib.Path] = []
    if allowlist_raw:
        for raw in allowlist_raw.split(os.pathsep):
            piece = raw.strip()
            if not piece:
                continue
            candidate = pathlib.Path(piece)
            if not candidate.is_absolute():
                candidate = (base_dir / candidate).resolve()
            allow_paths.append(candidate)

    timeout_seconds: float | None = None
    timeout_raw = os.environ.get("KPP_SANDBOX_TIMEOUT", "").strip()
    if timeout_raw:
        try:
            timeout_seconds = float(timeout_raw)
        except ValueError as exc:
            raise RuntimeError("KPP_SANDBOX_TIMEOUT must be a valid number of seconds.") from exc
        if timeout_seconds <= 0:
            raise RuntimeError("KPP_SANDBOX_TIMEOUT must be greater than zero.")

    env_allow_raw = os.environ.get("KPP_SANDBOX_ENV_ALLOW", "").strip()
    sandbox_env: dict[str, str] = {}
    if env_allow_raw:
        for key in env_allow_raw.split(","):
            env_name = key.strip()
            if not env_name:
                continue
            if env_name in os.environ:
                sandbox_env[env_name] = os.environ[env_name]

    return SandboxOptions(
        allow_paths=tuple(allow_paths),
        timeout_seconds=timeout_seconds,
        env=sandbox_env,
    )


def _is_path_allowed(path: pathlib.Path, allow_paths: tuple[pathlib.Path, ...]) -> bool:
    for allowed in allow_paths:
        try:
            path.relative_to(allowed)
            return True
        except ValueError:
            continue
    return False


def _artifact_label(artifact: ScriptArtifact) -> str:
    return artifact.name or f"artifact_{artifact.hash[:8]}"


def _artifact_dependency_order(root: ScriptArtifact) -> list[ScriptArtifact]:
    ordered: list[ScriptArtifact] = []
    state: dict[int, int] = {}
    trail: list[ScriptArtifact] = []

    def dfs(node: ScriptArtifact) -> None:
        marker = state.get(id(node), 0)
        if marker == 1:
            cycle_nodes = trail + [node]
            cycle_repr = " -> ".join(_artifact_label(item) for item in cycle_nodes)
            raise RuntimeError(f"Dependency cycle detected: {cycle_repr}")
        if marker == 2:
            return

        state[id(node)] = 1
        trail.append(node)
        for dep in node.dependencies:
            if not isinstance(dep, ScriptArtifact):
                raise RuntimeError(
                    f'Script variable "{_artifact_label(node)}" has a non-script dependency.'
                )
            dfs(dep)
        trail.pop()
        state[id(node)] = 2
        ordered.append(node)

    dfs(root)
    return ordered


def _dependency_hash_salt(artifact: ScriptArtifact) -> str:
    if not artifact.dependencies:
        return ""
    hashes = ",".join(dep.hash for dep in artifact.dependencies)
    return f"deps:{hashes}"


def _prepare_artifact_build(
    artifact: ScriptArtifact,
    base_dir: pathlib.Path,
    dry_run: bool,
) -> None:
    lang = _normalized_language(artifact.language)
    family = _compiled_language_family(lang)
    if family is None:
        return
    _compile_inline_with_cache(
        family=family,
        source_code=artifact.source,
        base_dir=base_dir,
        dry_run=dry_run,
        extra_material=_dependency_hash_salt(artifact),
    )


def _install_logging_artifact_guard() -> object:
    import logging

    original_handle_error = logging.Handler.handleError

    def guarded_handle_error(self: logging.Handler, record: logging.LogRecord) -> None:
        _, exc_value, _ = sys.exc_info()
        if isinstance(exc_value, RuntimeError) and str(exc_value) == SCRIPT_ARTIFACT_PRINT_ERROR:
            raise exc_value
        original_handle_error(self, record)

    logging.Handler.handleError = guarded_handle_error
    return original_handle_error


def _restore_logging_artifact_guard(previous_handle_error: object) -> None:
    import logging

    logging.Handler.handleError = previous_handle_error


def _execute_native_python_script(
    code: str,
    display_name: str,
    base_dir: pathlib.Path,
    dry_run: bool,
) -> None:
    if dry_run:
        print("$", "kpp-native-python", display_name)
        return

    script_globals: dict[str, object] = {
        "__name__": "__main__",
        "__file__": display_name,
        "__package__": None,
    }

    previous_argv = sys.argv[:]
    previous_cwd = pathlib.Path.cwd()
    previous_logging_handle_error = _install_logging_artifact_guard()
    sys.argv = [display_name]

    try:
        os.chdir(base_dir)
        exec(compile(code, display_name, "exec"), script_globals, script_globals)
    except SystemExit as exc:
        exit_code = exc.code
        if exit_code in (None, 0):
            return
        raise RuntimeError(f"Native Python exited with code {exit_code}") from exc
    except Exception:
        traceback.print_exc()
        raise RuntimeError(f"Native Python script failed: {display_name}") from None
    finally:
        sys.argv = previous_argv
        os.chdir(previous_cwd)
        _restore_logging_artifact_guard(previous_logging_handle_error)


def _execute_sandboxed_python_script(
    code: str,
    display_name: str,
    base_dir: pathlib.Path,
    dry_run: bool,
    sandbox_options: SandboxOptions,
) -> None:
    if dry_run:
        print("$", "kpp-native-python-sandbox", display_name)
        return

    safe_builtins: dict[str, object] = {
        "abs": builtins.abs,
        "all": builtins.all,
        "any": builtins.any,
        "bool": builtins.bool,
        "dict": builtins.dict,
        "enumerate": builtins.enumerate,
        "float": builtins.float,
        "int": builtins.int,
        "len": builtins.len,
        "list": builtins.list,
        "max": builtins.max,
        "min": builtins.min,
        "print": builtins.print,
        "range": builtins.range,
        "set": builtins.set,
        "str": builtins.str,
        "tuple": builtins.tuple,
        "zip": builtins.zip,
        "Exception": builtins.Exception,
        "RuntimeError": builtins.RuntimeError,
    }

    def safe_open(file: object, mode: str = "r", *args: object, **kwargs: object) -> object:
        if not sandbox_options.allow_paths:
            raise RuntimeError(
                "Sandbox filesystem access denied. Configure KPP_SANDBOX_ALLOW_PATHS to allow paths."
            )
        candidate = pathlib.Path(str(file))
        resolved = candidate if candidate.is_absolute() else (base_dir / candidate).resolve()
        if not _is_path_allowed(resolved, sandbox_options.allow_paths):
            raise RuntimeError(f"Sandbox denied filesystem access: {resolved}")
        return builtins.open(resolved, mode, *args, **kwargs)

    blocked_modules = {
        "socket",
        "urllib",
        "http",
        "ftplib",
        "ssl",
        "asyncio",
        "subprocess",
        "requests",
    }
    original_import = builtins.__import__

    def safe_import(
        name: str,
        globals_obj: dict[str, object] | None = None,
        locals_obj: dict[str, object] | None = None,
        fromlist: tuple[str, ...] | list[str] = (),
        level: int = 0,
    ) -> object:
        root_name = name.split(".")[0]
        if root_name in blocked_modules:
            raise RuntimeError(f'Sandbox blocked import of module "{root_name}".')
        return original_import(name, globals_obj, locals_obj, fromlist, level)

    safe_builtins["open"] = safe_open
    safe_builtins["__import__"] = safe_import

    script_globals: dict[str, object] = {
        "__name__": "__main__",
        "__file__": display_name,
        "__package__": None,
        "__builtins__": safe_builtins,
    }

    previous_argv = sys.argv[:]
    previous_cwd = pathlib.Path.cwd()
    previous_logging_handle_error = _install_logging_artifact_guard()

    import socket

    original_socket = socket.socket
    original_create_connection = getattr(socket, "create_connection", None)

    def blocked_socket(*args: object, **kwargs: object) -> object:
        raise RuntimeError("Sandbox network access is disabled.")

    socket.socket = blocked_socket  # type: ignore[assignment]
    if original_create_connection is not None:
        socket.create_connection = blocked_socket  # type: ignore[assignment]

    previous_environ = os.environ.copy()
    os.environ.clear()
    os.environ.update(sandbox_options.env)

    timer_installed = False
    previous_timer_handler = None
    timeout_seconds = sandbox_options.timeout_seconds
    if timeout_seconds is not None:
        if not hasattr(signal, "SIGALRM"):
            raise RuntimeError("Sandbox timeout is unavailable on this platform.")
        previous_timer_handler = signal.getsignal(signal.SIGALRM)

        def handle_timeout(signum: int, frame: object) -> None:
            raise RuntimeError("Sandbox execution timed out.")

        signal.signal(signal.SIGALRM, handle_timeout)
        signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
        timer_installed = True

    sys.argv = [display_name]

    try:
        os.chdir(base_dir)
        exec(compile(code, display_name, "exec"), script_globals, script_globals)
    except SystemExit as exc:
        exit_code = exc.code
        if exit_code in (None, 0):
            return
        raise RuntimeError(f"Sandboxed Python exited with code {exit_code}") from exc
    finally:
        if timer_installed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            if previous_timer_handler is not None:
                signal.signal(signal.SIGALRM, previous_timer_handler)

        os.environ.clear()
        os.environ.update(previous_environ)
        socket.socket = original_socket  # type: ignore[assignment]
        if original_create_connection is not None:
            socket.create_connection = original_create_connection  # type: ignore[assignment]
        _restore_logging_artifact_guard(previous_logging_handle_error)
        sys.argv = previous_argv
        os.chdir(previous_cwd)


def _run_compiled_binary(
    binary_path: pathlib.Path,
    base_dir: pathlib.Path,
    dry_run: bool,
    sandboxed: bool,
    sandbox_options: SandboxOptions | None = None,
) -> None:
    if not sandboxed:
        _run_command([str(binary_path)], cwd=base_dir, dry_run=dry_run)
        return

    if sandbox_options is None:
        raise RuntimeError("Sandbox configuration unavailable for compiled execution.")

    with tempfile.TemporaryDirectory(prefix="kpp_sandbox_exec_") as sandbox_dir:
        _run_command(
            [str(binary_path)],
            cwd=pathlib.Path(sandbox_dir),
            dry_run=dry_run,
            env=sandbox_options.env,
            timeout_seconds=sandbox_options.timeout_seconds,
        )


def _run_source_code(
    language: str,
    code: str,
    base_dir: pathlib.Path,
    dry_run: bool,
    sandboxed: bool = False,
    cache_extra_material: str = "",
) -> None:
    lang = _normalized_language(language)

    if lang in ("python", "python3", "py"):
        if sandboxed:
            sandbox_options = _load_sandbox_options(base_dir)
            _execute_sandboxed_python_script(
                code=code,
                display_name="<kpp-inline-python>",
                base_dir=base_dir,
                dry_run=dry_run,
                sandbox_options=sandbox_options,
            )
        else:
            _execute_native_python_script(
                code=code,
                display_name="<kpp-inline-python>",
                base_dir=base_dir,
                dry_run=dry_run,
            )
        return

    if _is_web_artifact_language(lang):
        if sandboxed:
            raise RuntimeError(f'Sandboxed execution is unavailable for artifact language "{language}".')
        artifact_path = _write_temp_artifact(code, _artifact_suffix(lang))
        _open_in_browser(artifact_path, cwd=base_dir, dry_run=dry_run)
        return

    compiled_family = _compiled_language_family(lang)
    if compiled_family is not None:
        sandbox_options = _load_sandbox_options(base_dir) if sandboxed else None
        binary_path = _compile_inline_with_cache(
            family=compiled_family,
            source_code=code,
            base_dir=base_dir,
            dry_run=dry_run,
            extra_material=cache_extra_material,
        )
        _run_compiled_binary(
            binary_path=binary_path,
            base_dir=base_dir,
            dry_run=dry_run,
            sandboxed=sandboxed,
            sandbox_options=sandbox_options,
        )
        return

    if sandboxed:
        raise RuntimeError(
            f'Sandboxed execution is currently unavailable for interpreted language "{language}".'
        )

    with tempfile.TemporaryDirectory(prefix="kpp_") as tmp:
        tmp_dir = pathlib.Path(tmp)

        if lang in ("bash", "sh", "shell"):
            script = tmp_dir / "inline.sh"
            script.write_text(code, encoding="utf-8")
            _run_command(["bash", str(script)], cwd=base_dir, dry_run=dry_run)
            return

        if lang in ("javascript", "js", "node"):
            script = tmp_dir / "inline.js"
            script.write_text(code, encoding="utf-8")
            _run_command(["node", str(script)], cwd=base_dir, dry_run=dry_run)
            return

        ext = _language_extension(language)
        script = tmp_dir / f"inline.{ext}"
        script.write_text(code, encoding="utf-8")
        runtime = _runtime_command(language)
        _run_command([runtime, str(script)], cwd=base_dir, dry_run=dry_run)


def _run_existing_file(
    language: str,
    path_value: str,
    base_dir: pathlib.Path,
    dry_run: bool,
    sandboxed: bool = False,
    cache_extra_material: str = "",
) -> None:
    target = (
        pathlib.Path(path_value)
        if pathlib.Path(path_value).is_absolute()
        else (base_dir / path_value).resolve()
    )

    if not target.exists():
        raise RuntimeError(f"File not found for run.file.language: {path_value}")

    lang = _normalized_language(language)

    if _is_web_artifact_language(lang):
        if sandboxed:
            raise RuntimeError(f'Sandboxed execution is unavailable for artifact language "{language}".')
        _open_in_browser(target, cwd=base_dir, dry_run=dry_run)
        return

    if lang in ("python", "python3", "py"):
        code = target.read_text(encoding="utf-8")
        if sandboxed:
            sandbox_options = _load_sandbox_options(base_dir)
            _execute_sandboxed_python_script(
                code=code,
                display_name=str(target),
                base_dir=base_dir,
                dry_run=dry_run,
                sandbox_options=sandbox_options,
            )
        else:
            _execute_native_python_script(
                code=code,
                display_name=str(target),
                base_dir=base_dir,
                dry_run=dry_run,
            )
        return

    compiled_family = _compiled_language_family(lang)
    if compiled_family is not None:
        source_code = target.read_text(encoding="utf-8")
        sandbox_options = _load_sandbox_options(base_dir) if sandboxed else None
        binary_path = _compile_file_with_cache(
            family=compiled_family,
            source_path=target,
            source_code=source_code,
            base_dir=base_dir,
            dry_run=dry_run,
            extra_material=cache_extra_material,
        )
        _run_compiled_binary(
            binary_path=binary_path,
            base_dir=base_dir,
            dry_run=dry_run,
            sandboxed=sandboxed,
            sandbox_options=sandbox_options,
        )
        return

    if sandboxed:
        raise RuntimeError(
            f'Sandboxed execution is currently unavailable for interpreted language "{language}".'
        )

    if lang in ("bash", "sh", "shell"):
        _run_command(["bash", str(target)], cwd=base_dir, dry_run=dry_run)
        return

    if lang in ("javascript", "js", "node"):
        _run_command(["node", str(target)], cwd=base_dir, dry_run=dry_run)
        return

    runtime = _runtime_command(language)
    _run_command([runtime, str(target)], cwd=base_dir, dry_run=dry_run)


def _first_program_start_line(lines: list[str]) -> int | None:
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == PROGRAM_START:
            return idx
        return None
    return None


def _normalize_run_file_path_arg(path_arg: str, line_no: int) -> str:
    token = path_arg.strip()
    if not token:
        raise KppSyntaxError(f"line {line_no}: missing file path in run.file.language")

    if token[0] in ('"', "'"):
        try:
            ast.literal_eval(token)
        except (SyntaxError, ValueError) as exc:
            raise KppSyntaxError(f"line {line_no}: invalid quoted file path") from exc
        return token

    # Bare file paths like hello.cpp should stay literal strings.
    # Unquoted identifiers are treated as Python variable expressions.
    if token.isidentifier():
        return token
    return repr(token)


def _normalize_emit_output_arg(path_arg: str, line_no: int) -> str:
    token = path_arg.strip()
    if not token:
        raise KppSyntaxError(f"line {line_no}: missing output path in emit.language")

    if token[0] in ('"', "'"):
        try:
            ast.literal_eval(token)
        except (SyntaxError, ValueError) as exc:
            raise KppSyntaxError(f"line {line_no}: invalid quoted output path") from exc
        return token

    if token.isidentifier():
        return token
    return repr(token)


def _normalize_define_dependencies(depends_arg: str | None, line_no: int) -> str:
    if depends_arg is None or not depends_arg.strip():
        return "[]"

    parts = [piece for piece in re.split(r"[,\s]+", depends_arg.strip()) if piece]
    if not parts:
        return "[]"

    for dep_name in parts:
        if not dep_name.isidentifier():
            raise KppSyntaxError(
                f'line {line_no}: invalid dependency "{dep_name}". Use script variable names.'
            )

    return "[" + ", ".join(parts) + "]"


def _parse_run_language_target(target_expr: str, line_no: int) -> tuple[str, bool]:
    token = target_expr.strip()
    if not token:
        raise KppSyntaxError(f"line {line_no}: missing script variable/expression")

    sandboxed = False
    if token.endswith(" sandboxed"):
        sandboxed = True
        token = token[: -len(" sandboxed")].rstrip()
        if not token:
            raise KppSyntaxError(f"line {line_no}: missing script variable before sandboxed")

    return token, sandboxed


def transform_kpp_to_python(source: str) -> str:
    lines = source.splitlines()
    out_lines: list[str] = []

    program_start_line = _first_program_start_line(lines)
    index = 0
    while index < len(lines):
        raw = lines[index]

        if program_start_line is not None and index == program_start_line:
            out_lines.append("")
            index += 1
            continue

        define_match = DEFINE_RE.match(raw)
        if define_match:
            indent, name, language, depends_arg = define_match.groups()

            if index + 1 >= len(lines) or lines[index + 1].strip() != BLOCK_DELIMITER:
                raise KppSyntaxError(
                    f"line {index + 1}: expected {BLOCK_DELIMITER!r} after define for {name!r}"
                )

            block_start = index + 2
            cursor = block_start
            block_lines: list[str] = []
            while cursor < len(lines) and lines[cursor].strip() != BLOCK_DELIMITER:
                block_lines.append(lines[cursor])
                cursor += 1

            if cursor >= len(lines):
                raise KppSyntaxError(f"line {index + 1}: unclosed define block for {name!r}")

            block_code = "\n".join(block_lines)
            if block_code:
                block_code += "\n"

            dependency_expr = _normalize_define_dependencies(depends_arg, line_no=index + 1)
            out_lines.append(
                f"{indent}{name} = __kpp_define({language!r}, {block_code!r}, {name!r}, {dependency_expr})"
            )

            consumed_extra = cursor - index
            out_lines.extend("" for _ in range(consumed_extra))
            index = cursor + 1
            continue

        run_language_match = RUN_LANGUAGE_RE.match(raw)
        if run_language_match:
            indent, language, target_expr = run_language_match.groups()
            normalized_target_expr, sandboxed = _parse_run_language_target(target_expr, line_no=index + 1)
            out_lines.append(
                f"{indent}__kpp_run_language({language!r}, {normalized_target_expr}, sandboxed={sandboxed})"
            )
            index += 1
            continue

        run_file_match = RUN_FILE_LANGUAGE_RE.match(raw)
        if run_file_match:
            indent, language, path_arg = run_file_match.groups()
            path_expr = _normalize_run_file_path_arg(path_arg, line_no=index + 1)
            out_lines.append(f"{indent}__kpp_run_file_language({language!r}, {path_expr})")
            index += 1
            continue

        emit_language_match = EMIT_LANGUAGE_RE.match(raw)
        if emit_language_match:
            indent, language, target_expr, output_arg = emit_language_match.groups()
            target_expr = target_expr.strip()
            if not target_expr:
                raise KppSyntaxError(f"line {index + 1}: missing script variable/expression in emit.language")
            output_expr = _normalize_emit_output_arg(output_arg, line_no=index + 1)
            out_lines.append(f"{indent}__kpp_emit_language({language!r}, {target_expr}, {output_expr})")
            index += 1
            continue

        out_lines.append(raw)
        index += 1

    transformed = "\n".join(out_lines)
    if source.endswith("\n"):
        transformed += "\n"
    return transformed


def run_kpp_program(
    kpp_path: pathlib.Path,
    source: str,
    script_args: list[str],
    dry_run: bool,
) -> None:
    transformed = transform_kpp_to_python(source)
    base_dir = kpp_path.resolve().parent
    emitted_paths: set[pathlib.Path] = set()

    def _require_script_artifact(value: object, context: str) -> ScriptArtifact:
        if isinstance(value, ScriptArtifact):
            return value
        raise RuntimeError(f"{context} expects a script variable.")

    def _kpp_type(*args: object) -> object:
        if len(args) == 1 and isinstance(args[0], ScriptArtifact):
            return "script"
        return builtins.type(*args)

    def _kpp_lang(value: object) -> str:
        artifact = _require_script_artifact(value, "lang()")
        return artifact.language

    def _kpp_origin(value: object) -> str:
        artifact = _require_script_artifact(value, "origin()")
        return artifact.origin

    def _kpp_hash(value: object) -> object:
        if isinstance(value, ScriptArtifact):
            return value.hash
        return builtins.hash(value)

    def _artifact_suffix_for_language(language_name: str) -> str:
        normalized = _normalized_language(language_name)
        if _is_web_artifact_language(normalized):
            return _artifact_suffix(normalized)
        return "." + _language_extension(normalized)

    def _ensure_language_match(language_name: str, artifact: ScriptArtifact) -> None:
        requested = _normalized_language(language_name)
        actual = _normalized_language(artifact.language)
        if requested != actual:
            raise RuntimeError(
                f'Language mismatch for script variable "{artifact.name or "<anonymous>"}": '
                f'defined as "{artifact.language}", run as "{language_name}"'
            )

    def _build_dependencies_for(artifact: ScriptArtifact) -> None:
        dependency_order = _artifact_dependency_order(artifact)
        for dep in dependency_order[:-1]:
            _prepare_artifact_build(dep, base_dir=base_dir, dry_run=dry_run)

    def _resolve_output_path(path_value: object) -> pathlib.Path:
        if isinstance(path_value, ScriptArtifact):
            raise RuntimeError("emit.language output path cannot be a script variable.")
        raw = pathlib.Path(str(path_value))
        resolved = raw if raw.is_absolute() else (base_dir / raw).resolve()
        return resolved

    def _register_emitted_path(path_value: pathlib.Path) -> None:
        if path_value in emitted_paths:
            raise RuntimeError(f"emit.language output path collision: {path_value}")
        emitted_paths.add(path_value)

    def _default_dependency_emit_path(
        dependency: ScriptArtifact,
        output_dir: pathlib.Path,
        reserved: set[pathlib.Path],
    ) -> pathlib.Path:
        base_name = dependency.name if dependency.name else f"artifact_{dependency.hash[:8]}"
        safe_base = re.sub(r"[^A-Za-z0-9_.-]", "_", base_name)
        if not safe_base:
            safe_base = f"artifact_{dependency.hash[:8]}"
        suffix = _artifact_suffix_for_language(dependency.language)

        candidate = output_dir / f"{safe_base}{suffix}"
        if candidate not in reserved and candidate not in emitted_paths:
            return candidate

        counter = 1
        while True:
            candidate = output_dir / f"{safe_base}_{dependency.hash[:8]}_{counter}{suffix}"
            if candidate not in reserved and candidate not in emitted_paths:
                return candidate
            counter += 1

    def _emit_artifact(language_name: str, artifact: ScriptArtifact, output_path_value: object) -> None:
        _ensure_language_match(language_name, artifact)
        dependency_order = _artifact_dependency_order(artifact)
        root_output = _resolve_output_path(output_path_value)
        reserved: set[pathlib.Path] = set(emitted_paths)
        reserved.add(root_output)
        dep_outputs: list[tuple[ScriptArtifact, pathlib.Path]] = []
        for dep in dependency_order[:-1]:
            dep_path = _default_dependency_emit_path(dep, root_output.parent, reserved)
            reserved.add(dep_path)
            dep_outputs.append((dep, dep_path))

        for dep, dep_path in dep_outputs:
            _register_emitted_path(dep_path)
            dep_path.parent.mkdir(parents=True, exist_ok=True)
            dep_path.write_text(dep.source, encoding="utf-8")

        _register_emitted_path(root_output)
        root_output.parent.mkdir(parents=True, exist_ok=True)
        root_output.write_text(artifact.source, encoding="utf-8")

    def _kpp_define(
        language: str,
        code: str,
        name: str | None = None,
        dependencies: object | None = None,
    ) -> ScriptArtifact:
        dep_values: list[ScriptArtifact] = []
        if dependencies is None:
            dep_values = []
        elif isinstance(dependencies, ScriptArtifact):
            dep_values = [dependencies]
        elif isinstance(dependencies, (list, tuple)):
            for dep_item in dependencies:
                if not isinstance(dep_item, ScriptArtifact):
                    raise RuntimeError(
                        "define ... depends only accepts script variables as dependencies."
                    )
                dep_values.append(dep_item)
        else:
            raise RuntimeError("define ... depends must be a script variable or list of script variables.")

        return ScriptArtifact(
            name=name or "<kpp-script>",
            language=language,
            source=code,
            origin="inline",
            dependencies=dep_values,
        )

    def _kpp_run_language(language: str, script_ref: object, sandboxed: bool = False) -> None:
        if isinstance(script_ref, ScriptArtifact):
            _ensure_language_match(language, script_ref)
            _build_dependencies_for(script_ref)
            _run_source_code(
                script_ref.language,
                script_ref.source,
                base_dir=base_dir,
                dry_run=dry_run,
                sandboxed=sandboxed,
                cache_extra_material=_dependency_hash_salt(script_ref),
            )
            return

        if isinstance(script_ref, str):
            _run_source_code(
                language,
                script_ref,
                base_dir=base_dir,
                dry_run=dry_run,
                sandboxed=sandboxed,
            )
            return

        raise RuntimeError(
            "run.language expects a script created with define\"...\" or a string code expression"
        )

    def _run_artifact_as_file(language: str, artifact: ScriptArtifact, sandboxed: bool = False) -> None:
        _ensure_language_match(language, artifact)
        _build_dependencies_for(artifact)

        suffix = _artifact_suffix_for_language(artifact.language)
        temp_path = _write_temp_artifact(artifact.source, suffix=suffix)
        _run_existing_file(
            language,
            str(temp_path),
            base_dir=base_dir,
            dry_run=dry_run,
            sandboxed=sandboxed,
            cache_extra_material=_dependency_hash_salt(artifact),
        )

    def _kpp_run_file_language(language: str, path_value: object) -> None:
        if isinstance(path_value, ScriptArtifact):
            _run_artifact_as_file(language, path_value)
            return
        if isinstance(path_value, pathlib.Path):
            _run_existing_file(language, str(path_value), base_dir=base_dir, dry_run=dry_run)
            return
        if isinstance(path_value, str):
            _run_existing_file(language, path_value, base_dir=base_dir, dry_run=dry_run)
            return
        raise RuntimeError(
            "run.file.language expects a file path (str/pathlib.Path) or a script variable."
        )

    def _kpp_emit_language(language: str, script_ref: object, output_path: object) -> None:
        artifact = _require_script_artifact(script_ref, "emit.language")
        _emit_artifact(language, artifact, output_path)

    runtime_globals: dict[str, object] = {
        "__name__": "__main__",
        "__file__": str(kpp_path),
        "__package__": None,
        "__kpp_define": _kpp_define,
        "__kpp_run_language": _kpp_run_language,
        "__kpp_run_file_language": _kpp_run_file_language,
        "__kpp_emit_language": _kpp_emit_language,
        "kpp": KppRuntimeAPI(),
        "type": _kpp_type,
        "lang": _kpp_lang,
        "origin": _kpp_origin,
        "hash": _kpp_hash,
    }

    previous_argv = sys.argv[:]
    previous_cwd = pathlib.Path.cwd()
    previous_logging_handle_error = _install_logging_artifact_guard()

    try:
        sys.argv = [str(kpp_path), *script_args]
        os.chdir(base_dir)
        exec(compile(transformed, str(kpp_path), "exec"), runtime_globals, runtime_globals)
    except SystemExit as exc:
        exit_code = exc.code
        if exit_code in (None, 0):
            return
        raise RuntimeError(f"K++ program exited with code {exit_code}") from exc
    finally:
        sys.argv = previous_argv
        os.chdir(previous_cwd)
        _restore_logging_artifact_guard(previous_logging_handle_error)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="K++ interpreter (Python-compatible with K++ language tweaks)"
    )
    parser.add_argument("file", help="Path to a .kpp script")
    parser.add_argument("--dry-run", action="store_true", help="Print external commands instead of executing")
    parser.add_argument("--emit-python", action="store_true", help="Print transformed Python and exit")
    args, script_args = parser.parse_known_args(argv)
    if script_args and script_args[0] == "--":
        script_args = script_args[1:]

    kpp_path = pathlib.Path(args.file)
    try:
        source = kpp_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"File not found: {kpp_path}", file=sys.stderr)
        return 1

    try:
        transformed = transform_kpp_to_python(source)
        if args.emit_python:
            print(transformed, end="")
            return 0

        run_kpp_program(
            kpp_path=kpp_path,
            source=source,
            script_args=script_args,
            dry_run=args.dry_run,
        )
    except KppSyntaxError as exc:
        print(f"Syntax error: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"Runtime error: {exc}", file=sys.stderr)
        return 1
    except Exception:
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
