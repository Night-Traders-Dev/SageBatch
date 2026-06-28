# SageBatch Benchmarks
Comparing Interpreter mode vs SageVM (AOT compilation) mode.

## Loop Benchmark (1000 iterations)
```
Interpreter Mode:

real	0m0.097s
user	0m0.074s
sys	0m0.022s
AOT Mode:
benchmarks/run.sh: line 3: 2007725 Segmentation fault         (core dumped) ./build/sagebatch benchmarks/loop.bat

real	0m1.111s
user	0m0.000s
sys	0m0.002s
```

## Fibonacci Benchmark (200 iterations)
```
Interpreter Mode:

real	0m0.036s
user	0m0.021s
sys	0m0.015s
AOT Mode:
benchmarks/run.sh: line 3: 2007734 Segmentation fault         (core dumped) ./build/sagebatch benchmarks/fib.bat

real	0m1.099s
user	0m0.000s
sys	0m0.002s
```

## Math Benchmark (Factorial 100)
```
Interpreter Mode:

real	0m0.026s
user	0m0.011s
sys	0m0.015s
AOT Mode:
benchmarks/run.sh: line 3: 2007743 Segmentation fault         (core dumped) ./build/sagebatch benchmarks/math.bat

real	0m1.084s
user	0m0.000s
sys	0m0.001s
```

## Nested Loops Benchmark (50x50)
```
Interpreter Mode:

real	0m0.154s
user	0m0.138s
sys	0m0.016s
AOT Mode:
benchmarks/run.sh: line 3: 2007752 Segmentation fault         (core dumped) ./build/sagebatch benchmarks/nested_loop.bat

real	0m1.091s
user	0m0.000s
sys	0m0.002s
```
