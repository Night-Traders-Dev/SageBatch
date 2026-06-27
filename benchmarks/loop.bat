@ECHO OFF
ECHO Starting nested loop benchmark
FOR %%A IN (1 2 3 4 5 6 7 8 9 10) DO (
    FOR %%B IN (1 2 3 4 5 6 7 8 9 10) DO (
        FOR %%C IN (1 2 3 4 5 6 7 8 9 10) DO (
            FOR %%D IN (1 2 3 4 5 6 7 8 9 10) DO (
                REM do nothing
            )
        )
    )
)
ECHO Done
