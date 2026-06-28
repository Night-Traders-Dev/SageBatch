@echo off
set COUNT=0
:loop
echo This is a test line for echo performance benchmarking
set /A COUNT=COUNT+1
if "%COUNT%"=="500" goto end
goto loop
:end
echo Echo performance benchmark done