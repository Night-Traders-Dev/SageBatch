@echo off
set I=0
:outer
set J=0
:inner
set /A J=J+1
if "%J%"=="50" goto next_outer
goto inner
:next_outer
set /A I=I+1
if "%I%"=="50" goto end
goto outer
:end
echo Done nested loops
