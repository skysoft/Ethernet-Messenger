#Requires -Version 5.1
<#
    maak_snelkoppeling.ps1
    Maakt een snelkoppeling op het bureaublad naar Ethernet Messenger
    (Windows-versie), die automatisch als Administrator start.

    Gebruik:
        powershell -ExecutionPolicy Bypass -File .\maak_snelkoppeling.ps1 -AppPad "C:\pad\naar\ethernet_messenger_windows.py"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$AppPad
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $AppPad)) {
    Write-Host "FOUT: kan '$AppPad' niet vinden." -ForegroundColor Red
    exit 1
}

# PATH verversen vanuit het register: een eerdere installatiestap kan
# Python net hebben geinstalleerd, wat nog niet zichtbaar is in het
# procesgeheugen van dit (net gestarte) PowerShell-proces.
$machinePad = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
$gebruikerPad = [System.Environment]::GetEnvironmentVariable("Path", "User")
$env:Path = "$machinePad;$gebruikerPad"

$python = $null
try {
    $uitvoer = & py -3 -c "import sys; print(sys.executable)" 2>$null
    if ($LASTEXITCODE -eq 0 -and $uitvoer) { $python = ($uitvoer | Select-Object -Last 1) }
} catch { }
if (-not $python) {
    $commando = Get-Command python -ErrorAction SilentlyContinue
    if ($commando) { $python = $commando.Source }
}
if (-not $python -or -not (Test-Path $python)) {
    Write-Host "FOUT: kan python.exe niet vinden. Is de installatie van Python wel gelukt?" -ForegroundColor Red
    exit 1
}

$bureaublad = [Environment]::GetFolderPath("Desktop")
$snelkoppelingPad = Join-Path $bureaublad "Ethernet Messenger.lnk"

$WshShell = New-Object -ComObject WScript.Shell
$Snelkoppeling = $WshShell.CreateShortcut($snelkoppelingPad)
$Snelkoppeling.TargetPath = $python
$Snelkoppeling.Arguments = "`"$AppPad`""
$Snelkoppeling.WorkingDirectory = Split-Path $AppPad -Parent
$Snelkoppeling.IconLocation = $python
$Snelkoppeling.Description = "Ethernet Messenger (CCNA-lesmateriaal)"
$Snelkoppeling.Save()

# De snelkoppeling moet altijd als Administrator starten (nodig voor raw
# sockets/Npcap). Dat vinkje ("Als administrator uitvoeren") zit niet in
# de WScript.Shell-API, maar is 1 bit in het .lnk-bestand zelf: byte 0x15,
# bit 0x20 (bevestigd: dit is dezelfde bit die Windows zelf zet/wist).
$bytes = [System.IO.File]::ReadAllBytes($snelkoppelingPad)
$bytes[0x15] = $bytes[0x15] -bor 0x20
[System.IO.File]::WriteAllBytes($snelkoppelingPad, $bytes)

Write-Host "Snelkoppeling aangemaakt: $snelkoppelingPad" -ForegroundColor Green
