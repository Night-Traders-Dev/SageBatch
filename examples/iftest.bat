@ECHO OFF
REM IF / EXIST / ERRORLEVEL demo
IF EXIST hello.bat ECHO hello.bat found
IF NOT EXIST missing.txt ECHO missing.txt does not exist

SET X=hello
IF %X% == hello ECHO X is hello
IF NOT %X% == world ECHO X is not world
