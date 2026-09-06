#Requires -Version 5.1
<#
    installeer_windows.ps1
    Installeert alle afhankelijkheden voor Ethernet Messenger (Windows-versie)
    op een Windows 10/11-laptop: Python 3, Npcap, PyQt6 + Scapy, en optioneel
    Wireshark.

    Gebruik (in PowerShell):
        powershell -ExecutionPolicy Bypass -File .\installeer_windows.ps1

    Parameters:
        -MetWireshark      installeer Wireshark zonder ernaar te vragen
        -ZonderWireshark   sla Wireshark over zonder ernaar te vragen
#>

param(
    [switch]$MetWireshark,
    [switch]$ZonderWireshark
)

$ErrorActionPreference = "Stop"

function Schrijf-Stap($tekst) {
    Write-Host ""
    Write-Host "==> $tekst" -ForegroundColor Cyan
}

function Schrijf-Ok($tekst) {
    Write-Host "    OK: $tekst" -ForegroundColor Green
}

function Schrijf-Waarschuwing($tekst) {
    Write-Host "    LET OP: $tekst" -ForegroundColor Yellow
}

function Schrijf-Fout($tekst) {
    Write-Host "    FOUT: $tekst" -ForegroundColor Red
}

function Vernieuw-PadOmgevingsvariabele {
    $machinePad = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $gebruikerPad = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machinePad;$gebruikerPad"
}

# Windows plaatst standaard een "App execution alias"-stub voor python.exe
# op het PAD die, als Python niet echt geinstalleerd is, alleen een
# doorverwijzing naar de Microsoft Store toont in plaats van een fout te
# geven. Get-Command vindt die stub dus altijd, ook zonder echte Python-
# installatie — en met $ErrorActionPreference "Stop" wordt de stderr-tekst
# van die stub een afbrekende fout in plaats van gewoon een niet-nul
# exitcode. Daarom hier een aparte, robuuste check die de echte output leest.
function Test-PythonGeinstalleerd {
    try {
        $output = & py -3 --version 2>&1
        if ($LASTEXITCODE -eq 0 -and "$output" -match '^Python \d') { return $true }
    } catch { }
    try {
        $output = & python --version 2>&1
        if ($LASTEXITCODE -eq 0 -and "$output" -match '^Python \d') { return $true }
    } catch { }
    return $false
}

# Gebruikt bij voorkeur de 'py'-launcher, want die is niet gevoelig voor
# de App-execution-alias-valkuil hierboven.
function Voer-Python([string[]]$pythonArgs) {
    try {
        & py -3 @pythonArgs
        return
    } catch { }
    & python @pythonArgs
}

# --- Zichzelf verhogen naar Administrator indien nodig ---
# Npcap-installatie en het draaien van Ethernet Messenger zelf vereisen
# Administrator-rechten, dus vraagt dit script dat meteen op zodat de rest
# van de installatie in één keer doorloopt.
$huidigePrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $huidigePrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Dit installatiescript heeft Administrator-rechten nodig. Opnieuw starten als Administrator..." -ForegroundColor Yellow
    $scriptPad = $MyInvocation.MyCommand.Path
    $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$scriptPad`"")
    if ($MetWireshark) { $args += "-MetWireshark" }
    if ($ZonderWireshark) { $args += "-ZonderWireshark" }
    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs
    exit
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Ethernet Messenger - installatie van afhankelijkheden (Windows) " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# --- winget controleren ---
Schrijf-Stap "Controleren of winget (Windows Package Manager) beschikbaar is..."
$wingetAanwezig = Get-Command winget -ErrorAction SilentlyContinue
if (-not $wingetAanwezig) {
    Schrijf-Fout "winget is niet gevonden. Dit hoort standaard bij Windows 10/11."
    Schrijf-Fout "Installeer of update 'App Installer' via de Microsoft Store en start dit script opnieuw:"
    Schrijf-Fout "https://apps.microsoft.com/detail/9nblggh4nns1"
    exit 1
}
Schrijf-Ok "winget is beschikbaar."

# --- Python 3 ---
Schrijf-Stap "Controleren of Python 3 is geinstalleerd..."
if (Test-PythonGeinstalleerd) {
    Schrijf-Ok "Python is al geinstalleerd."
} else {
    Schrijf-Stap "Python 3 wordt geinstalleerd via winget..."
    winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements
    Vernieuw-PadOmgevingsvariabele
    if (Test-PythonGeinstalleerd) {
        Schrijf-Ok "Python is geinstalleerd."
    } else {
        Schrijf-Waarschuwing "Python-installatie afgerond, maar nog niet bruikbaar in dit venster."
        Schrijf-Waarschuwing "Sluit dit PowerShell-venster en start het script opnieuw."
        Schrijf-Waarschuwing "Zie je de melding 'Python was not found... App execution aliases'? Schakel"
        Schrijf-Waarschuwing "dan de aliassen voor python.exe/python3.exe uit via Instellingen > Apps >"
        Schrijf-Waarschuwing "Geavanceerde app-instellingen > App-uitvoeraliassen."
        exit 1
    }
}

# --- Npcap ---
# Belangrijk: de gratis (niet-OEM) Npcap-installer ondersteunt GEEN silent
# install (/S is alleen beschikbaar in Npcap OEM, zie npcap.com). Dit script
# downloadt daarom de officiele installer en start die interactief; de
# student moet zelf even door de installatiewizard klikken (standaardopties
# aanhouden is voldoende).
Schrijf-Stap "Controleren of Npcap is geinstalleerd..."
$npcapAanwezig = (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll") -or (Get-Service -Name npcap -ErrorAction SilentlyContinue)
if ($npcapAanwezig) {
    Schrijf-Ok "Npcap is al geinstalleerd."
} else {
    Schrijf-Stap "Npcap wordt gedownload..."
    $npcapUrl = "https://npcap.com/dist/npcap-1.88.exe"
    $npcapBestand = Join-Path $env:TEMP "npcap-installer.exe"
    Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapBestand
    Schrijf-Ok "Download voltooid: $npcapBestand"

    Schrijf-Waarschuwing "De Npcap-installatiewizard opent nu. De gratis versie kan niet automatisch"
    Schrijf-Waarschuwing "(silent) worden geinstalleerd, dus doorloop de wizard even handmatig:"
    Schrijf-Waarschuwing "klik op 'I Agree' / 'Install' en laat de standaardopties staan."
    Start-Process -FilePath $npcapBestand -Wait

    $npcapAanwezig = (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll") -or (Get-Service -Name npcap -ErrorAction SilentlyContinue)
    if ($npcapAanwezig) {
        Schrijf-Ok "Npcap is geinstalleerd."
    } else {
        Schrijf-Waarschuwing "Npcap lijkt niet geinstalleerd te zijn. Ethernet Messenger kan zonder Npcap"
        Schrijf-Waarschuwing "geen frames bouwen, versturen of ontvangen. Installeer Npcap alsnog via:"
        Schrijf-Waarschuwing $npcapUrl
    }
}

# --- PyQt6 en Scapy ---
Schrijf-Stap "PyQt6 en Scapy installeren via pip..."
Voer-Python @("-m", "pip", "install", "--upgrade", "pip")
Voer-Python @("-m", "pip", "install", "PyQt6", "scapy")
if ($LASTEXITCODE -ne 0) {
    Schrijf-Fout "Installeren van PyQt6/Scapy via pip is mislukt (zie foutmelding hierboven)."
    exit 1
}
Schrijf-Ok "PyQt6 en Scapy zijn geinstalleerd."

# --- Wireshark (optioneel) ---
Schrijf-Stap "Controleren of Wireshark is geinstalleerd..."
$wiresharkAanwezig = (Get-Command wireshark -ErrorAction SilentlyContinue) `
    -or (Test-Path "$env:ProgramFiles\Wireshark\wireshark.exe") `
    -or (Test-Path "${env:ProgramFiles(x86)}\Wireshark\wireshark.exe")

if ($wiresharkAanwezig) {
    Schrijf-Ok "Wireshark is al geinstalleerd."
} elseif ($ZonderWireshark) {
    Schrijf-Waarschuwing "Wireshark wordt overgeslagen (parameter -ZonderWireshark)."
} elseif ($MetWireshark) {
    Schrijf-Stap "Wireshark wordt geinstalleerd via winget..."
    winget install --id WiresharkFoundation.Wireshark -e --silent --accept-package-agreements --accept-source-agreements
    Schrijf-Ok "Wireshark is geinstalleerd."
} else {
    $antwoord = Read-Host "Wireshark installeren? Optioneel, alleen nodig voor de knop 'Open in Wireshark'. (j/N)"
    if ($antwoord -match '^[jJ]') {
        Schrijf-Stap "Wireshark wordt geinstalleerd via winget..."
        winget install --id WiresharkFoundation.Wireshark -e --silent --accept-package-agreements --accept-source-agreements
        Schrijf-Ok "Wireshark is geinstalleerd."
    } else {
        Schrijf-Ok "Wireshark wordt overgeslagen."
    }
}

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Installatie voltooid " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Start Ethernet Messenger als volgt:"
Write-Host "  1. Open een NIEUW PowerShell- of Opdrachtprompt-venster ALS ADMINISTRATOR"
Write-Host "     (rechtermuisknop op het programma -> 'Als administrator uitvoeren')."
Write-Host "  2. Navigeer naar de map met dit project."
Write-Host "  3. Voer uit: python ethernet_messenger_windows.py"
Write-Host ""
Write-Host "Zie README_windows.md voor meer uitleg."
Write-Host ""
Read-Host "Druk op Enter om dit venster te sluiten"
