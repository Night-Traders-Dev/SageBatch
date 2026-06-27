@echo off
set I=0
:loop
set /A I=I+1
if "%I%"=="1000" goto end
goto loop
:end
echo Done loop
