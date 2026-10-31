param(
    [string]$Python = 'python'
)

$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    & $Python -m PyInstaller --noconfirm --clean --onefile --windowed `
        --name APIKeyLeak --icon app.ico --add-data 'app.ico;.' gui.py
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed with exit code $LASTEXITCODE"
    }
    $exe = Join-Path $PSScriptRoot 'dist\APIKeyLeak.exe'
    if (-not (Test-Path -LiteralPath $exe)) {
        throw 'Build did not produce dist\APIKeyLeak.exe'
    }
    Get-Item -LiteralPath $exe | Select-Object FullName, Length, LastWriteTime
}
finally {
    Pop-Location
}
