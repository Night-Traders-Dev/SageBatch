@ECHO OFF
REM Counter example using GOTO as a loop
SET COUNT=0

:LOOP
SET /A COUNT=%COUNT%+1
ECHO Count: %COUNT%
IF %COUNT% == 5 GOTO DONE
GOTO LOOP

:DONE
ECHO Done! Final count: %COUNT%
