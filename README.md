# K++ Language

`K++` is a Python-compatible interpreter with syntax tweaks for multi-language execution.

## Core model

- Normal Python code runs natively inside the K++ interpreter.
- K++ adds extra statements for embedding and running other languages.

## Syntax tweaks

- Optional program start marker: `"prgm.start"`
- Define embedded script:
  - `<name>=define"<language>"`
  - block delimited by lines exactly equal to `\\\`
- Run embedded script: `run.language "<language>" <name>`
- Run external file: `run.file.language "<language>" <path>`

## Script variable semantics 

Script variables represent executable or renderable programs, not data values.

Allowed:

- `run.language "<lang>" prog`
- `run.file.language "<lang>" prog`
- Passing script variables through execution-oriented APIs
- Storing and reassigning script variables internally

Forbidden:

- `print(prog)`
- `str(prog)`
- `f"{prog}"`
- Logging/string interpolation that stringifies script variables
- String concatenation with script variables

If stringification is attempted, K++ raises:

- `Script variables are executable artifacts and cannot be printed.`

## Example (K++)

```kpp
"prgm.start"

print("Python execution is native in K++")

rustscript=define"rust"
\\\
fn main() {
    println!("Hello from Rust!");
}
\\\

run.language "rust" rustscript
```

## Run

```bash
python3 kpp.py syntax.kpp
```

## Emit transformed Python

```bash
python3 kpp.py syntax.kpp --emit-python
```

## Dry run

```bash
python3 kpp.py syntax.kpp --dry-run
```

`--dry-run` prints external commands instead of executing them.

## Input behavior

If nested language programs prompt for input (`input`, `cin`, etc.), K++ passes terminal I/O through so users can respond normally.

## Language execution behavior

- Native in-process: `python`
- Rendered artifacts (not executed): `html`, `css`
- Built-in compile/run: `rust`, `c++`, `c`, `go`
- Other languages: runtime fallback by language name/alias (for example `ruby`, `php`, `node`)

## Compiled language guarantees

- Inline compiled code is supported through `define"<lang>"` blocks.
- Inline compiled sources are written to temporary source files before compilation.
- Compilation uses system compilers (`gcc`, `g++`, `rustc`, `go build`).
- Compiled binaries are cached by content hash to avoid unnecessary recompiles.
- Compiled programs run as binaries with stdin/stdout/stderr forwarded directly.
- Compiler diagnostics are shown verbatim from the compiler.
- Compiled languages are never treated as interpreted runtimes.

## HTML/CSS behavior

- `run.file.language "html" <file>`: opens the file in the default browser.
- `run.file.language "css" <file>`: opens the file in the default browser.
- `run.language "html" <var>`: writes the inline block to a temp `.html` file and opens it.
- `run.language "css" <var>`: writes the inline block to a temp `.css` file and opens it.
- K++ does not parse HTML/CSS; they are treated as rendered artifacts.
- Python code can still generate HTML/CSS files normally, then open them via `run.file.language`.

## Build one single binary
- Clone the repo
- cd into `build`
- Run the following

```bash
python3 -m venv .venv
.venv/bin/python -m pip install pyinstaller
.venv/bin/python -m PyInstaller --onefile --name kpp kpp.py
```

Binary output:

- `dist/kpp`

## Test suite

Run local tests:

```bash
make test-interpreter
make test-security
```

Run all:

```bash
make test
```
