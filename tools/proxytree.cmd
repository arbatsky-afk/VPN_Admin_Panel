@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul

set "PYTHON=%~dp0..\.venv\Scripts\python.exe"
set "GENERATOR=%~dp0proxytree.py"

if not exist "%PYTHON%" (
    echo ERROR: virtual environment not found at "%PYTHON%".
    pause
    exit /b 1
)

echo Building the proxy tree from "%~dp0in"...
"%PYTHON%" "%GENERATOR%"
if errorlevel 1 (
    echo.
    echo Failed. The tree was not written.
    pause
    exit /b 1
)

echo Done: "%~dp0in\proxy-tree.yaml".
pause
exit /b 0
