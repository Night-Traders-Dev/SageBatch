@echo off
set A=0
set B=1
set COUNT=0
:loop
set /A C=A+B
set A=%B%
set B=%C%
set /A COUNT=COUNT+1
if "%COUNT%"=="200" goto end
goto loop
:end
echo Fibonacci 200 is %C%
