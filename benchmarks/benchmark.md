# SageBatch Benchmarks
Comparing Interpreter mode vs SageVM (AOT compilation) mode.

## Loop Benchmark (1000 iterations)
```
Interpreter Mode:

real	0m0.051s
user	0m0.040s
sys	0m0.011s
AOT Mode:

real	0m0.023s
user	0m0.022s
sys	0m0.001s
```

## Fibonacci Benchmark (200 iterations)
```
Interpreter Mode:

real	0m0.030s
user	0m0.016s
sys	0m0.014s
AOT Mode:

real	0m0.009s
user	0m0.008s
sys	0m0.001s
```
