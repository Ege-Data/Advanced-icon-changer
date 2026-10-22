@echo off
echo Building IconChanger...
g++ -O2 -municode -mwindows main.cpp -o IconChanger.exe -lcomctl32 -lcomdlg32 -lole32 -luuid -lshlwapi -ladvapi32
if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Build completed successfully: IconChanger.exe
) else (
    echo.
    echo [ERROR] Compilation failed.
)
pause
