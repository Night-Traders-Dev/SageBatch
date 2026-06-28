@echo off
set A=1
set B=2
set C=3
set D=4
set E=5
set COUNT=0
:loop
echo %A%%B%%C%%D%%E%
set /A COUNT=COUNT+1
if "%COUNT%"=="1000" goto end
goto loop
:end
echo Variable expansion benchmark done