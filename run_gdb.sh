#!/bin/bash
gdb -batch -ex "break exit" -ex "run" -ex "frame 2" -ex "p left" -ex "p right" --args ./build/sagebatch benchmarks/loop.bat
