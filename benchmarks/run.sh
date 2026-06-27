#!/bin/bash

run_benchmarks() {
    echo "## Loop Benchmark (1000 iterations)" >> benchmarks/benchmark.md
    echo "\`\`\`" >> benchmarks/benchmark.md
    echo "Interpreter Mode:" >> benchmarks/benchmark.md
    { time sage src/sage/batch.sage benchmarks/loop.bat ; } 2>> benchmarks/benchmark.md
    echo "AOT Mode:" >> benchmarks/benchmark.md
    { time ./build/sagebatch benchmarks/loop.bat ; } 2>> benchmarks/benchmark.md
    echo "\`\`\`" >> benchmarks/benchmark.md

    echo "" >> benchmarks/benchmark.md

    echo "## Fibonacci Benchmark (200 iterations)" >> benchmarks/benchmark.md
    echo "\`\`\`" >> benchmarks/benchmark.md
    echo "Interpreter Mode:" >> benchmarks/benchmark.md
    { time sage src/sage/batch.sage benchmarks/fib.bat ; } 2>> benchmarks/benchmark.md
    echo "AOT Mode:" >> benchmarks/benchmark.md
    { time ./build/sagebatch benchmarks/fib.bat ; } 2>> benchmarks/benchmark.md
    echo "\`\`\`" >> benchmarks/benchmark.md
}

echo "# SageBatch Benchmarks" > benchmarks/benchmark.md
echo "Comparing Interpreter mode vs SageVM (AOT compilation) mode." >> benchmarks/benchmark.md
echo "" >> benchmarks/benchmark.md

run_benchmarks
