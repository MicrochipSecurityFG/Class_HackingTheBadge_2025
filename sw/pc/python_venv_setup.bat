@echo off
setlocal enabledelayedexpansion

REM Detect OS (simple check based on OS variable)
if /i "%OS%"=="Windows_NT" (
    set "IS_WINDOWS=true"
) else (
    set "IS_WINDOWS=false"
)

REM Define paths
SET VENV_PATH=%cd%\venv
SET TARGET_DIR=%cd%
SET REQUIREMENTS_FILE=%cd%\requirements.txt

REM Check if venv exists
IF NOT EXIST "%VENV_PATH%" (
    echo Creating virtual environment in %VENV_PATH%...
    python -m venv "%VENV_PATH%"
    echo Virtual environment created.
) ELSE (
    echo Virtual environment already exists.
)

REM Activate virtual environment
echo Activating virtual environment...
call "%VENV_PATH%\Scripts\activate.bat"

REM Check if requirements.txt exists
IF EXIST "%REQUIREMENTS_FILE%" (
    echo Found requirements.txt, installing packages...
    pip install -r "%REQUIREMENTS_FILE%"
    
) else (
	echo ****MISSING requirements.txt****
	echo Aborting
	goto :error
)

REM Deactivate virtual environment
call "%VENV_PATH%\Scripts\deactivate.bat"

REM Launch a new shell with venv activated
start cmd.exe /k "TITLE venv & %VENV_PATH%\Scripts\activate.bat & cd /d %TARGET_DIR% & echo Virtual environment activated."

echo Setup complete.

exit /b

:error

pause
