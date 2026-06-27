# SageBatch Benchmarks
Comparing Interpreter mode vs SageVM (AOT compilation) mode.

## Loop Benchmark (1000 iterations)
```
Interpreter Mode:

real	0m0.045s
user	0m0.032s
sys	0m0.013s
AOT Mode:
Runtime Error: Operands must be numbers, strings, or arrays.

real	0m0.026s
user	0m0.025s
sys	0m0.001s
```

## Fibonacci Benchmark (200 iterations)
```
Interpreter Mode:

real	0m0.033s
user	0m0.026s
sys	0m0.007s
AOT Mode:
benchmarks/run.sh: line 3: 1810767 Segmentation fault         (core dumped) ./build/sagebatch benchmarks/fib.bat

real	0m1.102s
user	0m0.001s
sys	0m0.002s
```
