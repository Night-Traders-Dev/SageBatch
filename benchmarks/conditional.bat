@echo off
set COUNT=0
:loop
if "%COUNT%"=="0" echo zero
if "%COUNT%"=="1" echo one
if "%COUNT%"=="2" echo two
if "%COUNT%"=="3" echo three
if "%COUNT%"=="4" echo four
set /A COUNT=COUNT+1
if "%COUNT%"=="1000" goto end
goto loop
:end
echo Conditional branching benchmark done