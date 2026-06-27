#!/bin/bash
echo "=== Interpreter Mode ==="
time ../deps/SageLang/core/sage ../src/sage/batch.sage loop.bat

echo ""
echo "=== SageVM Mode ==="
../deps/SageLang/core/sage --emit-vm ../src/sage/batch.sage -o sagebatch.svm
time ../deps/SageLang/core/sage --run-vm sagebatch.svm loop.bat
