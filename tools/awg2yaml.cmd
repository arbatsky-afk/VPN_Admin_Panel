@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul

set "PROJECT_ROOT=%~dp0.."
set "PYTHON=%PROJECT_ROOT%\.venv\Scripts\python.exe"
set "CONVERTER=%~dp0awg2yaml.py"
set "INBOX=%~dp0in"

if not exist "%PYTHON%" (
    echo ERROR: virtual environment not found at "%PYTHON%".
    pause
    exit /b 1
)

set /a CONVERTED=0
set /a FAILED=0

if not "%~1"=="" goto :dropped_files

if not exist "%INBOX%\" mkdir "%INBOX%"
for %%F in ("%INBOX%\*.conf" "%INBOX%\*.vpn") do call :convert "%%~fF"
if %CONVERTED%==0 if %FAILED%==0 (
    echo No .conf or .vpn files in "%INBOX%".
    echo Put the AmneziaWG configs there and run this script again.
    pause
    exit /b 0
)
goto :summary

:dropped_files
for %%F in (%*) do call :convert "%%~fF"
goto :summary

:convert
echo Converting "%~nx1"...
"%PYTHON%" "%CONVERTER%" "%~1"
if errorlevel 1 (
    set /a FAILED+=1
) else (
    set /a CONVERTED+=1
    echo   -^> "%~n1.yaml"
)
exit /b 0

:summary
echo.
echo Converted: %CONVERTED%, failed: %FAILED%.
pause
exit /b 0
