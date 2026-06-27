# SageBatch Benchmarks

This document contains benchmark results comparing the performance of SageBatch running under different execution models. The benchmarks measure the overhead of parsing and executing batch scripts.

## Test Script: `loop.bat`
A simple loop test that iterates and echoes numbers:
```bat
@echo off
set count=0
:loop
set /a count=count+1
if %count%==100 goto end
goto loop
:end
echo "Done"
```

## Results

### Interpreter Mode
Running via the raw SageLang AST tree-walker interpreter (`sage batch.sage loop.bat`):

*   **Real Time:** `~0.021s`
*   **User Time:** `~0.012s`
*   **Sys Time:**  `~0.009s`

*Interpreter mode successfully tokenizes, parses, and executes the script very quickly, taking only around 20ms.*

### SageVM Mode
Compiling to `.svm` bytecode and executing it on the SageVirtualMachine:

*   **Real Time:** N/A (Failed to Execute)
*   **User Time:** N/A
*   **Sys Time:** N/A

*Note: Compiling `batch.sage` using `sage --emit-vm` succeeds and generates a `sagebatch.svm` bytecode file. However, executing this bytecode file currently results in `Runtime Error: Undefined variable 'string'` due to a known bug in the `SageLang` upstream VM backend parser. The `sage --sgvm` native bytecode target currently segfaults on compilation.*
