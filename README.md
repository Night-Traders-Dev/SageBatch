# SageBatch

MS-DOS Batch 4.0 clone implemented entirely in SageLang, built on SageVM/SageLang as submodules, intended for integration with SageOS.

## Layout

```
/SageBatch
  /src
    /c
    /sage
  /deps
    SageLang
    SageVM
```

SageLang is built by running:

```bash
./sagesync
./sagemake --make-only
```
