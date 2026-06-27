# SageBatch

> A clean-room MS-DOS Batch 4.0 clone implemented entirely in [SageLang](https://github.com/Night-Traders-Dev/SageLang), running on [SageVM](https://github.com/Night-Traders-Dev/SageVM).

SageBatch is a faithful, modular reimplementation of the classic MS-DOS batch command processor — the engine behind `.BAT` files from the DOS 5.0 / 6.x era. Every component is written in pure Sage (with optional C glue for native I/O acceleration), structured as single-responsibility modules so each piece of the interpreter pipeline can be developed, tested, and replaced independently.

The project serves three purposes:

1. **Compatibility** — run real `.BAT` files from the DOS era with correct `ERRORLEVEL`, variable expansion, `GOTO` semantics, and argument handling.
2. **Education** — teach command-line automation through the lens of classic DOS scripting.
3. **SageOS integration** — become the default scripting layer for login scripts, build scripts, package scripts, and installers inside SageOS.

---

## Table of Contents

- [Repository Layout](#repository-layout)
- [Dependencies & Build](#dependencies--build)
- [Architecture Overview](#architecture-overview)
- [Execution Pipeline](#execution-pipeline)
- [Module Reference](#module-reference)
- [Internal Commands (V1)](#internal-commands-v1)
- [Language Features](#language-features)
- [DOS Compatibility Targets](#dos-compatibility-targets)
- [Runtime Objects](#runtime-objects)
- [Tests](#tests)
- [Examples](#examples)
- [Development Roadmap](#development-roadmap)
- [Long-Term Vision](#long-term-vision)

---

## Repository Layout

```
SageBatch/
├── src/
│   ├── sage/               # Pure Sage interpreter modules (one concern per file)
│   │   ├── token.sage      # Token constants and Token class
│   │   ├── lexer.sage      # Source → token stream
│   │   ├── ast.sage        # AST node definitions
│   │   ├── parser.sage     # Token stream → AST
│   │   ├── environment.sage # DOS environment block (PATH, TEMP, COMSPEC, PROMPT, CWD)
│   │   ├── varstore.sage   # Layered variable scope stack
│   │   ├── filesystem.sage # DOS-path semantics over Sage's io module
│   │   ├── commands.sage   # All V1 internal command implementations
│   │   ├── process.sage    # CommandContext + BatchProcess state machine
│   │   ├── registry.sage   # CommandRegistry dispatch table
│   │   ├── interpreter.sage # AST tree-walker (GOTO, IF, FOR, CALL, redirect, pipe)
│   │   └── batch.sage      # Entrypoint — script mode and interactive REPL
│   └── c/
│       └── README.md       # Placeholder for native glue (glob, ANSI, pipe buffers)
├── deps/
│   ├── SageLang/           # git submodule → Night-Traders-Dev/SageLang
│   └── SageVM/             # git submodule → Night-Traders-Dev/SageVM
├── examples/
│   ├── hello.bat
│   ├── counter.bat
│   ├── iftest.bat
│   └── forloop.bat
├── tests/
│   ├── test_lexer.sage
│   ├── test_parser.sage
│   ├── test_env.sage
│   └── test_interpreter.sage
├── BatchSage.md            # Full design specification
├── SageLang.md             # SageLang language reference (v3.9.4)
├── sagesetup.sh            # Bootstrap script — adds submodules and builds deps
└── README.md
```

---

## Dependencies & Build

SageBatch depends on two submodules: **SageLang** (the language runtime and compiler) and **SageVM** (the virtual machine backend). Neither is bundled — they are fetched and built locally.

### First-time setup

```bash
git clone https://github.com/Night-Traders-Dev/SageBatch
cd SageBatch
bash sagesetup.sh
```

`sagesetup.sh` performs the following steps automatically:

```bash
# 1. Register the submodules
git submodule add https://github.com/Night-Traders-Dev/SageLang deps/SageLang
git submodule add https://github.com/Night-Traders-Dev/SageVM   deps/SageVM

# 2. Build SageLang
cd deps/SageLang
./sagesync          # fetch native deps / headers
./sagemake --make-only  # compile the Sage interpreter

# 3. Build SageVM
cd ../SageVM
./sagesync
./sagemake --make-only
```

After the script completes, the `sage` binary is available at `deps/SageLang/sage` (or on your `PATH` if SageLang is installed system-wide).

### Subsequent clones

```bash
git clone --recurse-submodules https://github.com/Night-Traders-Dev/SageBatch
cd SageBatch
cd deps/SageLang && ./sagesync && ./sagemake --make-only
cd ../SageVM     && ./sagesync && ./sagemake --make-only
```

### Running a script

```bash
# Execute a .BAT file
sage src/sage/batch.sage examples/hello.bat

# Interactive REPL
sage src/sage/batch.sage

# Pass arguments to a batch script
sage src/sage/batch.sage myscript.bat arg1 arg2
```

---

## Architecture Overview

SageBatch is structured around five concerns, each mapped to a small set of Sage modules:

| Layer | Modules | Responsibility |
|-------|---------|----------------|
| **Lexical** | `token.sage`, `lexer.sage` | Tokenise raw `.BAT` source text |
| **Syntactic** | `ast.sage`, `parser.sage` | Build a typed abstract syntax tree |
| **Environment** | `environment.sage`, `varstore.sage` | DOS environment block and variable scoping |
| **Execution** | `interpreter.sage`, `process.sage`, `registry.sage` | Walk the AST and execute nodes |
| **Commands** | `commands.sage`, `filesystem.sage` | Implement each internal DOS command |

The entrypoint `batch.sage` wires all layers together, accepts a filename argument (script mode) or drops into a REPL (interactive mode).

---

## Execution Pipeline

```
.BAT source file
      │
      ▼
 ┌─────────┐      Token stream
 │  Lexer  │ ────────────────────►
 └─────────┘  token.sage + lexer.sage
                      │
                      ▼
              ┌────────────┐      Typed AST
              │   Parser   │ ──────────────►
              └────────────┘  ast.sage + parser.sage
                                    │
                                    ▼
                         ┌──────────────────┐
                         │   Interpreter    │  interpreter.sage
                         │                  │
                         │  ┌────────────┐  │
                         │  │ Environment│  │  environment.sage
                         │  │  VarStore  │  │  varstore.sage
                         │  └────────────┘  │
                         │  ┌────────────┐  │
                         │  │  Registry  │  │  registry.sage
                         │  │  Commands  │  │  commands.sage
                         │  │ FileSystem │  │  filesystem.sage
                         │  └────────────┘  │
                         │  ┌────────────┐  │
                         │  │  Process   │  │  process.sage
                         │  │  (CALL     │  │
                         │  │   stack)   │  │
                         │  └────────────┘  │
                         └──────────────────┘
                                    │
                                    ▼
                              stdout / files
```

The interpreter is a **tree-walking executor**. There is no intermediate bytecode pass in V1; that is deferred to a future compiler phase (see roadmap).

---

## Module Reference

### `token.sage`

Defines integer constants for every token kind (`TOK_WORD`, `TOK_STRING`, `TOK_VARIABLE`, `TOK_LABEL`, `TOK_REDIRECT_OUT`, `TOK_REDIRECT_APPEND`, `TOK_PIPE`, `TOK_AMP`, `TOK_AT`, `TOK_NEWLINE`, `TOK_EOF`) and the `Token(kind, value, line)` class that carries source location for error messages.

### `lexer.sage`

Consumes a raw `.BAT` string character-by-character and emits a flat list of `Token` objects. Key responsibilities:

- Recognise `%VAR%` (immediate expansion) and `!VAR!` (delayed expansion) as `TOK_VARIABLE`
- Emit `TOK_LABEL` for lines beginning with `:`
- Emit `TOK_REDIRECT_OUT` (`>`), `TOK_REDIRECT_APPEND` (`>>`), `TOK_PIPE` (`|`), `TOK_AMP` (`&`)
- Strip `@` echo-suppression prefix and emit `TOK_AT`
- Handle quoted strings as a single `TOK_STRING` token
- Track line numbers for error reporting

### `ast.sage`

Defines the node classes that form the AST. Every node stores its source line. Node types:

| Node | Fields | Description |
|------|--------|-------------|
| `Program` | `stmts[]` | Root of the tree |
| `Command` | `name`, `args[]`, `redirect`, `pipe_to` | A single executable command |
| `Assignment` | `name`, `value` | `SET VAR=value` |
| `IfStatement` | `condition`, `then_node`, `else_node` | `IF [NOT] ...` |
| `ForStatement` | `var`, `items`, `body` | `FOR %%A IN (...) DO ...` |
| `LabelNode` | `name` | `:LABEL` declaration |
| `GotoNode` | `target` | `GOTO LABEL` |
| `CallNode` | `filename`, `args[]` | `CALL script.bat` |
| `RedirectNode` | `target`, `path`, `append` | `> file` / `>> file` |
| `PipeNode` | `left`, `right` | `cmd1 \| cmd2` |
| `BlockNode` | `stmts[]` | Grouped statement sequence |

### `parser.sage`

Recursive-descent parser that consumes the token list produced by the lexer and returns a `Program` node. Dispatches on the first keyword of each line:

- `IF` → `parse_if()`
- `FOR` → `parse_for()`
- `GOTO` → `parse_goto()`
- `CALL` → `parse_call()`
- `SET` → `parse_assignment()`
- `TOK_LABEL` → `LabelNode`
- Anything else → `parse_command()` (handles `>`, `>>`, `|` suffixes)

### `environment.sage`

Holds the DOS environment block as a Sage dict. Pre-populates `PATH`, `TEMP`, `COMSPEC`, `PROMPT`, and `ERRORLEVEL`. Provides:

- `get(name)` / `set(name, value)` — case-insensitive lookup
- `expand(text)` — replace `%VAR%` tokens with their values
- `expand_delayed(text)` — replace `!VAR!` tokens (delayed expansion mode)
- `render_prompt()` — format the current prompt string for REPL display
- `set_cwd(path)` / `get_cwd()` — track current working directory

### `varstore.sage`

A stack of dicts that models DOS's flat environment but supports nested `FOR` loop variables without polluting the global scope. `push_scope()` / `pop_scope()` wrap each `FOR` body; `get()` / `set()` walk from innermost to outermost scope.

### `filesystem.sage`

Wraps SageLang's `io` module with DOS-path semantics:

- `normalize(path)` — convert backslashes, resolve `.` and `..`
- `resolve(path)` — anchor relative paths to the current working directory
- `copy(src, dst)`, `move(src, dst)`, `rename(src, dst)`, `delete(path)`
- `glob(pattern)` — stub returning files matching a DOS wildcard (`*.TXT`, `FILE?.BAT`)
- `list_dir(path)` — returns entries with size and date for `DIR` formatting

### `commands.sage`

Implements every V1 internal command as a `proc` that receives a `CommandContext`:

`ECHO` · `SET` · `REM` · `PAUSE` · `CLS` · `EXIT` · `CD` · `MD` · `RD` · `DIR` · `TYPE` · `COPY` · `MOVE` · `DEL` · `REN` · `SHIFT` · `VER` · `HELP`

Each command follows the same signature: `proc cmd_ECHO(ctx)` where `ctx` exposes `ctx.args`, `ctx.env`, `ctx.fs`, `ctx.stdout`, and `ctx.batch`.

### `process.sage`

**`CommandContext`** is the per-invocation state object: argument list (`%0`–`%9` plus the shifted register), stdout handle (file or console), current environment reference, and the parent `BatchProcess`.

**`BatchProcess`** is the top-level state machine for one `.BAT` execution: holds the parsed `Program`, the label table (built on first pass), the `CALL` return stack, the current statement index, and the `ERRORLEVEL` integer. Calling `BatchProcess.run()` starts the interpreter loop.

### `registry.sage`

A `CommandRegistry` class that holds a Sage dict mapping uppercase command names to their handler procs (registered by `commands.sage` at startup). `registry.dispatch(name, ctx)` looks up the handler and calls it, setting `ERRORLEVEL` on failure. Unknown names fall through to external-program execution (future work).

### `interpreter.sage`

The AST tree-walker. Key behaviours:

- **Label table** — on entry, scans the full `Program` for `LabelNode` entries and stores their statement indices; `GOTO` is then an O(1) index jump.
- **IF evaluation** — handles `IF EXIST <path>`, `IF ERRORLEVEL <n>`, `IF [NOT] <str1>==<str2>`, `IF [NOT] DEFINED <var>`.
- **FOR scope** — calls `varstore.push_scope()` before the loop body and `pop_scope()` after, preventing loop variables from leaking.
- **CALL nesting** — saves the current `BatchProcess` state, creates a child `BatchProcess` for the called script, runs it to completion, then restores the parent.
- **Redirect** — before executing a `Command` node that carries a `RedirectNode`, opens the target file and binds it to `ctx.stdout`; restores stdout on completion.
- **Pipe stub** — executes left command, captures output to an in-memory buffer, feeds it as stdin to the right command (byte-buffer native acceleration is planned for `src/c/`).

### `batch.sage`

Top-level entrypoint. When invoked with a filename argument it reads the file, runs it through the full pipeline, and exits with `ERRORLEVEL`. When invoked with no arguments it starts an interactive REPL that accepts one command per line, maintaining persistent environment state across prompts.

---

## Internal Commands (V1)

| Command | Syntax | Description |
|---------|--------|-------------|
| `ECHO` | `ECHO [ON\|OFF\|text]` | Print text or toggle echo |
| `SET` | `SET [VAR[=value]]` | Set, display, or clear a variable |
| `REM` | `REM [comment]` | Comment (no-op) |
| `PAUSE` | `PAUSE` | Wait for keypress |
| `CLS` | `CLS` | Clear screen |
| `EXIT` | `EXIT [/B] [code]` | Exit batch or shell |
| `CD` | `CD [path]` | Change or display current directory |
| `MD` | `MD path` | Create directory |
| `RD` | `RD [/S] path` | Remove directory |
| `DIR` | `DIR [path] [/W] [/P]` | List directory contents |
| `TYPE` | `TYPE file` | Print file to stdout |
| `COPY` | `COPY src dst` | Copy file |
| `MOVE` | `MOVE src dst` | Move file |
| `DEL` | `DEL file [/Q]` | Delete file(s) |
| `REN` | `REN old new` | Rename file |
| `SHIFT` | `SHIFT [/n]` | Shift argument registers |
| `VER` | `VER` | Display version string |
| `HELP` | `HELP [command]` | Show command help |

Control-flow keywords (`IF`, `FOR`, `GOTO`, `CALL`) are handled directly by the parser and interpreter rather than the command registry.

---

## Language Features

### Variables

```bat
SET NAME=Jacob
ECHO %NAME%          :: immediate expansion
SET /A COUNT=COUNT+1 :: arithmetic (planned)
SETLOCAL ENABLEDELAYEDEXPANSION
SET VAL=hello
ECHO !VAL!           :: delayed expansion
ENDLOCAL
```

### Labels and GOTO

```bat
:MENU
ECHO 1. Start
ECHO 2. Exit
SET /P CHOICE=Enter choice:
IF %CHOICE%==1 GOTO START
IF %CHOICE%==2 GOTO END
GOTO MENU

:START
ECHO Starting...
GOTO END

:END
```

Label resolution is O(1) via the label table built by the interpreter on first pass.

### Conditional Execution

```bat
IF EXIST file.txt ECHO Found
IF NOT DEFINED VAR SET VAR=default
IF ERRORLEVEL 1 ECHO Failed
IF %A%==%B% ECHO Equal
```

### Loops

```bat
:: List iteration
FOR %%A IN (apple banana cherry) DO ECHO %%A

:: File glob
FOR %%F IN (*.txt) DO TYPE %%F

:: Numeric (cmd-extensions, Phase 8)
FOR /L %%I IN (1,1,10) DO ECHO %%I
```

### I/O Redirection and Pipes

```bat
DIR > listing.txt
DIR >> listing.txt
TYPE file.txt | FIND "ERROR"
```

### CALL and argument passing

```bat
CALL worker.bat %1 %2
:: Inside worker.bat: %1 and %2 refer to the forwarded arguments
```

---

## DOS Compatibility Targets

| Target | Status |
|--------|--------|
| MS-DOS 5.0 core commands | Phase 5 |
| MS-DOS 6.x extensions (`DELTREE`, `CHOICE`) | Phase 8 |
| PC-DOS behaviour quirks | Phase 8 |
| Windows 95 `COMMAND.COM` semantics | Phase 8 |
| `SETLOCAL` / `ENDLOCAL` | Phase 5 |
| Delayed expansion (`!VAR!`) | Phase 4 |
| `FOR /L`, `FOR /F`, `FOR /R` | Phase 8 |
| `CALL :label` (internal subroutines) | Phase 7 |
| `ERRORLEVEL` propagation | Phase 5 |

---

## Runtime Objects

These Sage classes form the object model of the runtime:

| Class | Module | Role |
|-------|--------|------|
| `BatchProcess` | `process.sage` | Top-level execution state for one `.BAT` run |
| `Environment` | `environment.sage` | DOS environment block with variable expansion |
| `CommandContext` | `process.sage` | Per-command state: args, stdout, env, batch |
| `VariableStore` | `varstore.sage` | Layered scope stack for `FOR` variables |
| `FileSystem` | `filesystem.sage` | DOS-path-aware I/O wrapper |
| `CommandRegistry` | `registry.sage` | Dict-based command dispatch table |
| `ScriptExecutor` | `interpreter.sage` | AST tree-walker (the interpreter itself) |

---

## Tests

Each test file uses SageLang's `std.testing` module and targets exactly one layer:

```
tests/
├── test_lexer.sage       # Token output for representative .BAT snippets
├── test_parser.sage      # AST structure for IF, FOR, GOTO, CALL, redirect
├── test_env.sage         # Variable set/get, expansion, delayed expansion
└── test_interpreter.sage # End-to-end execution: GOTO jumps, CALL nesting,
                          #   ERRORLEVEL propagation, FOR scope isolation
```

Run all tests:

```bash
sage tests/test_lexer.sage
sage tests/test_parser.sage
sage tests/test_env.sage
sage tests/test_interpreter.sage
```

---

## Examples

```
examples/
├── hello.bat       # ECHO Hello World — smoke test
├── counter.bat     # FOR loop counting 1–10
├── iftest.bat      # IF / ELSE branching on %1
└── forloop.bat     # FOR %%F IN (*.bat) DO ECHO %%F
```

Run an example:

```bash
sage src/sage/batch.sage examples/counter.bat
```

---

## Development Roadmap

| Phase | Description | Key deliverables |
|-------|-------------|-----------------|
| **0** | Repository setup | Repo, submodules, `sagesetup.sh`, layout |
| **1** | Lexer | `token.sage`, `lexer.sage`, `test_lexer.sage` |
| **2** | Parser | `ast.sage`, `parser.sage`, `test_parser.sage` |
| **3** | Interpreter | `interpreter.sage`, `process.sage`, label table, GOTO |
| **4** | Environment | `environment.sage`, `varstore.sage`, `%VAR%` + `!VAR!` expansion |
| **5** | Internal commands | `commands.sage`, `registry.sage`, all V1 commands |
| **6** | File redirection | `filesystem.sage`, `>` / `>>` redirect in interpreter |
| **7** | Pipes | Byte-buffer pipe between commands; `src/c/` native helper |
| **8** | DOS compatibility | `FOR /L /F /R`, `CHOICE`, `DELTREE`, SETLOCAL, full test suite |
| **9** | BatchStudio IDE | Syntax highlighting, step debugger, variable watch window |

---

## Long-Term Vision

SageBatch is designed to run most educational DOS batch scripts unmodified, serve as a scripting engine for SageOS (login scripts, build scripts, package scripts, and installers), and provide a clean bridge between DOS-era automation knowledge and modern Sage development. The `src/c/` directory is reserved for native acceleration of hot paths — glob expansion, ANSI terminal control, and byte-level pipe buffers — all called from Sage via `ffi_open` / `ffi_call` as documented in the SageLang FFI reference.

---

## Related Projects

| Project | URL |
|---------|-----|
| SageLang | https://github.com/Night-Traders-Dev/SageLang |
| SageVM | https://github.com/Night-Traders-Dev/SageVM |
| SageOS | https://github.com/Night-Traders-Dev/SageOS |

---

*SageBatch is part of the Night-Traders-Dev open-source ecosystem. MIT License.*
