@ECHO OFF
CLS

REM Set a unique title for this command window
TITLE RestoreCommandWindow

ECHO ========== Closing Open Programs ============
ECHO.
TASKLIST | FIND "mplab_ide64.exe" > NUL
IF %errorlevel% == 0 (
    ECHO Closing MPLABX IDE...
    TASKKILL /F /IM mplab_ide64.exe
)
TASKLIST | FIND "Acrobat.exe" > NUL
IF %errorlevel% == 0 (
    ECHO Closing Adobe...
    TASKKILL /F /IM Acrobat.exe
)
TASKLIST | FIND "ttermpro.exe" > NUL
IF %errorlevel% == 0 (
    ECHO Closing Tera Term...
    TASKKILL /F /IM ttermpro.exe
)
FOR /F "tokens=2 delims=," %%i IN ('TASKLIST /FI "WINDOWTITLE eq venv" /FO CSV /NH') DO (
    ECHO Closing venv...
    TASKKILL /PID %%i /F
)

TIMEOUT /T 5 /NOBREAK > NUL

SETLOCAL ENABLEDELAYEDEXPANSION

REM Get the PID of the current command window based on the title
FOR /F "tokens=2 delims=," %%i IN ('TASKLIST /FI "WINDOWTITLE eq RestoreCommandWindow" /FO CSV /NH') DO (
    SET currentPID=%%i
)
ECHO Current command window PID is !currentPID!

REM PowerShell command to close all windows except the current one and exclude critical processes
ECHO About to execute PowerShell command
POWERSHELL -NoProfile -Command "$currentPID = !currentPID!; Write-Host 'Current PID:' $currentPID; $processes = Get-Process | Where-Object { $_.MainWindowHandle -ne 0 -and $_.Id -ne [int]$currentPID -and $_.ProcessName -ne 'winlogon' -and $_.ProcessName -ne 'taskhostw' -and $_.ProcessName -ne 'ApplicationFrameHost' -and $_.ProcessName -ne 'ShellExperienceHost' -and $_.ProcessName -ne 'SearchUI' }; foreach ($process in $processes) { Write-Host 'Found process:' $process.Id $process.ProcessName; if ($process.ProcessName -eq 'chrome' -or $process.ProcessName -eq 'explorer') { $process.Kill() | Out-Null } else { $process.CloseMainWindow() | Out-Null }; Start-Sleep -Seconds 1; }; Write-Host 'PowerShell command executed successfully';"
ECHO PowerShell command executed

ECHO.
ECHO All windows on the taskbar except the current one have been processed.
ECHO.

ECHO ========== Removing 25072_SEC3 working directory contents ============
ECHO.
RMDIR /S /Q "C:\MASTERs\25072_SEC3"
ECHO.

ECHO ========== Creating 25072_SEC3 working directory ============
ECHO.
MKDIR "C:\MASTERs\25072_SEC3"
ECHO.

ECHO ========== Finding the first ZIP file in the directory ============
ECHO.

REM Enable Delayed Expansion
SETLOCAL ENABLEDELAYEDEXPANSION

REM Set the directory to search for ZIP files
SET "searchDir=C:\Backup\25072_SEC3"

REM Initialize the variable to hold the first ZIP file found
SET "zipFile="

REM Loop through the files in the directory and find the first ZIP file
FOR %%F IN ("%searchDir%\*.zip") DO (
    SET "zipFile=%%F"
    ECHO Found ZIP file: !zipFile!
    GOTO :foundZip
)

:foundZip
IF NOT DEFINED zipFile (
    ECHO No ZIP file found in the directory.
    PAUSE
    ENDLOCAL
    EXIT /B
)

ECHO ========== Unzipping !zipFile! to temporary directory ============
ECHO.
POWERSHELL -Command "Expand-Archive -Path '!zipFile!' -DestinationPath 'C:\Temp\25072_SEC3'"
ECHO.

ECHO Unzipping completed.

ECHO ========== Moving unzipped files to working directory ============
ECHO.
REM Move all files and directories from the extracted first level directory to the target directory
FOR /D %%D IN ("C:\Temp\25072_SEC3\*") DO (
    ECHO Moving contents of %%D to C:\MASTERs\25072_SEC3
    ROBOCOPY "%%D" "C:\MASTERs\25072_SEC3" /E /MOVE /NFL /NDL /NJH /NJS
)
ECHO.

ECHO ========== Cleaning up temporary directory ============
RMDIR /S /Q "C:\Temp\25072_SEC3"
ECHO.

ECHO ========== Copying and Unzipping ghidra*.zip ============
ECHO.
IF EXIST "C:\MASTERs\25072_SEC3\ghidra*" (
    ECHO Ghidra directory already exists, skipping unzip.
) ELSE (
    SET "ghidraZip="
    FOR %%F IN ("%searchDir%\ghidra*.zip") DO (
        SET "ghidraZip=%%F"
        ECHO Found Ghidra ZIP file: !ghidraZip!
        COPY "!ghidraZip!" "C:\MASTERs\25072_SEC3"
        POWERSHELL -Command "Expand-Archive -Path 'C:\MASTERs\25072_SEC3\ghidra*.zip' -DestinationPath 'C:\MASTERs\25072_SEC3'"
        GOTO :ghidraDone
    )
    :ghidraDone
    IF NOT DEFINED ghidraZip (
        ECHO No Ghidra ZIP file found in the directory.
    )
)

ECHO ========== Copying and Unzipping openjdk*.zip ============
ECHO.
IF EXIST "C:\MASTERs\25072_SEC3\jdk*" (
    ECHO OpenJDK directory already exists, skipping unzip.
) ELSE (
    SET "jdkZip="
    FOR %%F IN ("%searchDir%\openjdk*.zip") DO (
        SET "jdkZip=%%F"
        ECHO Found OpenJDK ZIP file: !jdkZip!
        COPY "!jdkZip!" "C:\MASTERs\25072_SEC3"
        POWERSHELL -Command "Expand-Archive -Path 'C:\MASTERs\25072_SEC3\openjdk*.zip' -DestinationPath 'C:\MASTERs\25072_SEC3'"
        GOTO :jdkDone
    )
    :jdkDone
    IF NOT DEFINED jdkZip (
        ECHO No OpenJDK ZIP file found in the directory.
    )
)

ECHO ==================== UNZIPPING AND MOVING COMPLETE ==========================
ECHO.

ECHO ========== Creating Python virtual environment ============
ECHO.
CD "C:\MASTERs\25072_SEC3\sw\pc"
CALL "python_venv_setup.bat"
ECHO.

REM Call it twice to overcome a startup bug
CALL "python_venv_setup.bat"

ECHO ========== Opening Programs ============
ECHO.
START "" "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe" "C:\MASTERs\25072_SEC3\doc\LabManual.pdf"
START "" "C:\Program Files (x86)\teraterm\ttermpro.exe" /F="C:\MASTERs\25072_SEC3\sw\pc\TERATERM.INI"
START "" "C:\Program Files\Microchip\MPLABX\v6.25\mplab_platform\bin\mplab_ide64.exe" "C:\MASTERs\25072_SEC3\sw\wallet_firmware\firmware\wallet.X" --console new
ECHO.