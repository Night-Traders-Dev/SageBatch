# src/c — Native C Glue (optional)

This directory is reserved for any C-level extensions or FFI shims
that the pure-Sage modules in `src/sage/` cannot handle directly.

Examples of things that may land here:
- ANSI terminal control wrappers
- Fast glob / directory listing via `opendir`/`readdir`
- Pipe buffer implementations
- Low-level stdin/stdout byte-level control

Anything here will be compiled with SageLang's C backend and linked
via `ffiopen` / `ffical` from the Sage side.
