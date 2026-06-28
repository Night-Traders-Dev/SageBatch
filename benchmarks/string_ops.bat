@echo off
set STR=HelloWorld
set COUNT=0
:loop
set STR=HelloWorld
set /A COUNT=COUNT+1
if "%COUNT%"=="10000" goto end
goto loop
:end
echo String assignment benchmark done