@echo off
set I=0
:loop
set /A I=I+1
if "%I%"=="1000" goto end
if "%I%"=="999" echo %I%
goto loop
:end
echo Done loop
