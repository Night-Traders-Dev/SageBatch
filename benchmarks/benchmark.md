# SageBatch Benchmark Results

## loop.bat (1000 Iterations)

| Execution Mode | Runtime | Notes |
| :--- | :--- | :--- |
| **Interpreter (Native AOT)** | ~0.024s | Extremely fast MS-DOS parsing and AST execution due to SageLang C AOT backend. Stable after extensive GC corruption fixes. |
| **SageVM Mode** | *N/A (Failed)* | Cannot run multi-file projects on SageVM currently. `deps/SageLang/core/sage --sgvm` segfaults, and `sagevm run` does not support passing script arguments. Furthermore, bytecode compilation (`--emit-vm`) does not correctly bundle imported modules (`token`, `parser`, etc.). |

### Technical Details
- The AOT compiler compiles SageLang to native C which optimizes loops very effectively. 
- The GC heap corruption bug (throwing `Runtime Error: Operands must be numbers, strings, or arrays.`) was resolved by removing inline dictionary literals (which unroot each other) and extracting string allocation constants out of hot `while` loops inside the AST interpreter.
