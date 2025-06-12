@echo off
setlocal EnableDelayedExpansion

:: Create a directory for downloads if it doesn't exist
if not exist "downloads" mkdir downloads
cd downloads

:: Download the files using curl, but only if they don't already exist
if exist "Class_HackingTheBadge_2025.zip" (
    echo Class_HackingTheBadge_2025.zip already exists, skipping download...
) else (
    echo Downloading Class_HackingTheBadge_2025...
    curl -L -o Class_HackingTheBadge_2025.zip "https://github.com/MicrochipSecurityFG/Class_HackingTheBadge_2025/archive/refs/tags/entry_point_v0_6.zip"
)

if exist "ghidra_11.3.2_PUBLIC_20250415.zip" (
    echo ghidra_11.3.2_PUBLIC_20250415.zip already exists, skipping download...
) else (
    echo Downloading Ghidra...
    curl -L -o ghidra_11.3.2_PUBLIC_20250415.zip "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip"
)

if exist "openjdk-24.0.1_windows-x64_bin.zip" (
    echo openjdk-24.0.1_windows-x64_bin.zip already exists, skipping download...
) else (
    echo Downloading OpenJDK...
    curl -L -o openjdk-24.0.1_windows-x64_bin.zip "https://download.java.net/java/GA/jdk24.0.1/24a58e0e276943138bf3e963e6291ac2/9/GPL/openjdk-24.0.1_windows-x64_bin.zip"
)

:: Extract the specific file from Class_HackingTheBadge_2025 zip if the zip exists
if exist "Class_HackingTheBadge_2025.zip" (

       echo Extracting Class_HackingTheBadge_2025...
        mkdir Class_HackingTheBadge_2025
        powershell -command "Expand-Archive -Path Class_HackingTheBadge_2025.zip -DestinationPath Class_HackingTheBadge_2025" || (
            echo Error: Failed to extract Class_HackingTheBadge_2025.zip. The file may be corrupt or invalid.
            rmdir /s /q Class_HackingTheBadge_2025
            goto :cleanup
        )

        :: Extract the specific file 25072_SEC3_MASTERsPC_Restore.bat from sw/pc
        echo Copying the specific file...
        copy Class_HackingTheBadge_2025\Class_HackingTheBadge_2025-entry_point_v0_6\sw\pc\25072_SEC3_MASTERsPC_Restore.bat . || (
            echo Error: Failed to copy 25072_SEC3_MASTERsPC_Restore.bat. The file may not exist in the zip.
            rmdir /s /q Class_HackingTheBadge_2025
            goto :cleanup
        )

        :: Clean up
        echo Cleaning up...
        rmdir /s /q Class_HackingTheBadge_2025

) else (
    echo Class_HackingTheBadge_2025.zip not found, skipping extraction...
)

:cleanup
echo Done!
endlocal

pause