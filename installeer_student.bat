@echo off
setlocal

rem installeer_student.bat
rem Eenmalig te downloaden en te starten (als Administrator) door een
rem student. Haalt de Windows-versie van Ethernet Messenger en het
rem bijbehorende installatiescript rechtstreeks van GitHub op, installeert
rem alle afhankelijkheden, en zet een snelkoppeling op het bureaublad.

net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo Dit script heeft Administrator-rechten nodig, opnieuw starten...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo =================================================================
echo  Ethernet Messenger - installatie voor studenten
echo =================================================================
echo.

set "DOELMAP=%USERPROFILE%\EthernetMessenger"
set "REPO_RUW=https://raw.githubusercontent.com/skysoft/Ethernet-Messenger/main"

if not exist "%DOELMAP%" (
    echo Map aanmaken: %DOELMAP%
    mkdir "%DOELMAP%"
)

echo.
echo Stap 1/3: installatiescript downloaden en uitvoeren...
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri '%REPO_RUW%/installeer_windows.ps1' -OutFile '%DOELMAP%\installeer_windows.ps1'"
if errorlevel 1 (
    echo FOUT: downloaden van het installatiescript is mislukt. Controleer de internetverbinding.
    pause
    exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%DOELMAP%\installeer_windows.ps1"
if errorlevel 1 (
    echo FOUT: het installatiescript is mislukt, zie de meldingen hierboven.
    pause
    exit /b 1
)

echo.
echo Stap 2/3: Ethernet Messenger downloaden naar %DOELMAP%...
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri '%REPO_RUW%/ethernet_messenger_windows.py' -OutFile '%DOELMAP%\ethernet_messenger_windows.py'"
if errorlevel 1 (
    echo FOUT: downloaden van Ethernet Messenger is mislukt.
    pause
    exit /b 1
)

echo.
echo Stap 3/3: snelkoppeling op het bureaublad aanmaken...
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -Uri '%REPO_RUW%/maak_snelkoppeling.ps1' -OutFile '%TEMP%\maak_snelkoppeling.ps1'"
powershell -NoProfile -ExecutionPolicy Bypass -File "%TEMP%\maak_snelkoppeling.ps1" -AppPad "%DOELMAP%\ethernet_messenger_windows.py"

echo.
echo =================================================================
echo  Installatie voltooid!
echo =================================================================
echo Dubbelklik op "Ethernet Messenger" op het bureaublad om te starten
echo (deze start automatisch als Administrator).
echo.
pause
