# src/sage — SageBatch Pure-Sage Source

All batch interpreter logic lives here as independent modules.

| File | Phase | Description |
|------|-------|-------------|
| `token.sage` | 1 | Token type constants and `Token` class |
| `lexer.sage` | 1 | Tokenizer — converts `.BAT` source to token stream |
| `ast.sage` | 2 | AST node classes (`Program`, `Command`, `IfStatement`, …) |
| `parser.sage` | 2 | Recursive-descent parser, produces a `Program` AST |
| `environment.sage` | 4 | DOS environment block (PATH, TEMP, COMSPEC, ERRORLEVEL, CWD) |
| `varstore.sage` | 4 | Scoped variable store with `FOR`-loop isolation |
| `filesystem.sage` | 6 | DOS-like filesystem wrapper (normalize, glob, copy, move, …) |
| `commands.sage` | 5 | All V1 internal command implementations |
| `process.sage` | 5 | `BatchProcess` + `CommandContext` — execution state |
| `registry.sage` | 5 | `CommandRegistry` — dispatch table for internal commands |
| `interpreter.sage` | 3 | Tree-walking interpreter — GOTO, IF, FOR, CALL, pipes |
| `batch.sage` | — | **Entrypoint** — `sage src/sage/batch.sage script.bat [args]` |

## Build / Run

```bash
# Build SageLang first
cd deps/SageLang && ./sagesync && ./sagemake --make-only && cd ../..

# Run a batch script
sage src/sage/batch.sage examples/hello.bat

# Interactive mode
sage src/sage/batch.sage
```

## Milestones

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | ✅ | Repository setup |
| 1 | ✅ | Lexer |
| 2 | ✅ | Parser |
| 3 | ✅ | Interpreter (tree-walking) |
| 4 | ✅ | Environment variables |
| 5 | ✅ | Internal commands (V1) |
| 6 | ✅ | File redirection (`>`, `>>`, `<`) |
| 7 | 🚧 | Pipes (`|`) — stub |
| 8 | ⬜ | DOS compatibility suite |
| 9 | ⬜ | BatchStudio IDE |
