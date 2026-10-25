@echo off
setlocal
echo ==============================================================
echo   Building Advanced Icon Changer
echo ==============================================================

echo Compiling main.cpp with MinGW-w64 g++...
g++ -O2 -municode -mwindows main.cpp -o IconChanger.exe -lcomctl32 -lcomdlg32 -lole32 -luuid -lshlwapi -ladvapi32 -limagehlp

if errorlevel 1 goto FAIL

echo.
echo ==============================================================
echo   [SUCCESS] Advanced Icon Changer built successfully!
echo   Output: IconChanger.exe
echo   - Target-Centric Single File and Folder Customizer
echo   - Standalone Script Packager (.cmd / .bat to .exe)
echo   - Zero Impact on Global File Structure
echo   - Automatic UAC Administrator Elevation Enforced
echo ==============================================================
goto END

:FAIL
echo.
echo [ERROR] Build failed. Please verify MinGW g++ is in your PATH.

:END
pause
