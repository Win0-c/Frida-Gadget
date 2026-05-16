param(
    [Parameter(Position = 0)]
    [ValidateSet("menu", "find-gadget", "open-gadget", "dumper-help", "status")]
    [string] $Command = "menu"
)

$Workspace = Split-Path -Parent $PSScriptRoot
$FridaSource = Join-Path $Workspace "frida-source"
$GadgetDir = Join-Path $FridaSource "subprojects\frida-core\lib\gadget"
$GadgetMain = Join-Path $GadgetDir "gadget.vala"
$Dexdump = Join-Path $Workspace "frida-dexdump"
$DexdumpPython = Join-Path $Workspace ".venv-dexdump\Scripts\python.exe"

function Show-Menu {
    Write-Host ""
    Write-Host "Frida Gadget workspace"
    Write-Host "----------------------"
    Write-Host "Source:  $FridaSource"
    Write-Host "Gadget:  $GadgetMain"
    Write-Host "Dumper:  $Dexdump"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  .\tools\frida-workspace.ps1 find-gadget"
    Write-Host "  .\tools\frida-workspace.ps1 open-gadget"
    Write-Host "  .\tools\frida-workspace.ps1 dumper-help"
    Write-Host "  .\tools\frida-workspace.ps1 status"
    Write-Host ""
    Write-Host "Shortcut:"
    Write-Host "  .\frida-workspace.bat status"
}

function Get-Ripgrep {
    $installed = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages\BurntSushi.ripgrep.MSVC_Microsoft.Winget.Source_8wekyb3d8bbwe\ripgrep-15.1.0-x86_64-pc-windows-msvc\rg.exe"
    if (Test-Path -LiteralPath $installed) {
        return $installed
    }

    return "rg"
}

switch ($Command) {
    "menu" {
        Show-Menu
    }
    "find-gadget" {
        $rg = Get-Ripgrep
        & $rg --files $GadgetDir
    }
    "open-gadget" {
        if (-not (Test-Path -LiteralPath $GadgetMain)) {
            throw "Cannot find Gadget source: $GadgetMain"
        }

        notepad $GadgetMain
    }
    "dumper-help" {
        if (-not (Test-Path -LiteralPath $DexdumpPython)) {
            throw "Dumper venv is missing: $DexdumpPython"
        }

        & $DexdumpPython -m frida_dexdump --help
    }
    "status" {
        Write-Host "Workspace: $Workspace"
        Write-Host "Frida source exists: $(Test-Path -LiteralPath $FridaSource)"
        Write-Host "Gadget source exists: $(Test-Path -LiteralPath $GadgetMain)"
        Write-Host "Dumper source exists: $(Test-Path -LiteralPath $Dexdump)"
        Write-Host "Dumper venv exists: $(Test-Path -LiteralPath $DexdumpPython)"
        if (Test-Path -LiteralPath $DexdumpPython) {
            & $DexdumpPython -m frida_dexdump --help | Select-Object -First 4
        } else {
            Write-Host "frida-dexdump local environment is not ready yet."
        }
    }
}
