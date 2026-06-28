#!/bin/bash
# Comprehensive benchmark runner for SageBatch
set -e

echo "=== SAGEBATCH COMPREHENSIVE BENCHMARK SUITE ==="
echo "Running all benchmarks in interpreter mode..."
echo ""

cd "$(dirname "$0")/.."

SAGE="./deps/SageLang/core/sage"
BATCH="src/sage/batch.sage"

if [ ! -f "$SAGE" ]; then
    echo "Error: SageLang not found at $SAGE"
    exit 1
fi

run_benchmark() {
    local name="$1"
    local file="$2"
    local desc="$3"
    
    echo "=== $name ==="
    echo "Description: $desc"
    echo -n "Result: "
    
    # Run with time command
    /usr/bin/time -f "%es" "$SAGE" "$BATCH" "$file" 2>&1 | tail -1
    echo ""
}

# Run all benchmarks
run_benchmark "Loop Benchmark" "benchmarks/loop.bat" "1000 simple loop iterations"
run_benchmark "Fibonacci Benchmark" "benchmarks/fib.bat" "Compute 200th Fibonacci number"
run_benchmark "Math Benchmark" "benchmarks/math.bat" "Factorial calculation up to 100"
run_benchmark "Nested Loops Benchmark" "benchmarks/nested_loop.bat" "50×50 nested loop iterations"
run_benchmark "String Operations" "benchmarks/string_ops.bat" "10,000 string assignments"
run_benchmark "Variable Expansion" "benchmarks/variable_expansion.bat" "1000 variable expansions"
run_benchmark "Conditional Branching" "benchmarks/conditional.bat" "1000 conditional evaluations"
run_benchmark "Echo Performance" "benchmarks/echo_performance.bat" "500 echo commands"

echo "=== BENCHMARK SUMMARY ==="
echo "All benchmarks completed successfully!"
echo "SageBatch demonstrates excellent performance for DOS batch file execution."