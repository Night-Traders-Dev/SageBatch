@echo off
set RES=1
set N=1
:loop
set /A RES=RES*N
set /A N=N+1
if "%N%"=="100" goto end
goto loop
:end
echo Factorial 100 is %RES%
