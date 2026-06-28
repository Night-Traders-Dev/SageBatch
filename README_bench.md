# SageBatch Benchmarks
Comparing Interpreter mode vs SageVM (AOT compilation) mode.

## Loop Benchmark (1000 iterations)
```
Interpreter Mode:

real	0m0.056s
user	0m0.040s
sys	0m0.014s
AOT Mode:

real	0m0.022s
user	0m0.022s
sys	0m0.000s
```

## Fibonacci Benchmark (200 iterations)
```
Interpreter Mode:

real	0m0.028s
user	0m0.019s
sys	0m0.009s
AOT Mode:

real	0m0.009s
user	0m0.008s
sys	0m0.001s
```

## Math Benchmark (Factorial 100)
```
Interpreter Mode:

real	0m0.019s
user	0m0.010s
sys	0m0.009s
AOT Mode:
Runtime Error: no __class__ on instance (method=exec class_val_type=0).

real	0m0.002s
user	0m0.001s
sys	0m0.001s
```

## Nested Loops Benchmark (50x50)
```
Interpreter Mode:

real	0m0.114s
user	0m0.099s
sys	0m0.014s
AOT Mode:

real	0m0.043s
user	0m0.041s
sys	0m0.001s
```
