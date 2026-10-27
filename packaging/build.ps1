# Builds dist\VHServer-Setup-<version>.exe : tests -> PyInstaller folder build -> Inno Setup.
# Run from the project root:  powershell -ExecutionPolicy Bypass -File packaging\build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$version = (python -c "import vhserver; print(vhserver.__version__)").Trim()
Write-Host "Building VHServer $version"

python -m pytest tests -q
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

Remove-Item -Recurse -Force dist, build -ErrorAction SilentlyContinue
python -m PyInstaller packaging\vhserver.spec --noconfirm --distpath dist --workpath build
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 not found (https://jrsoftware.org/isinfo.php)" }
& $iscc "/DAppVersion=$version" "/DSourceDir=$root\dist\vhserver" packaging\installer.iss
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }

$setup = "dist\VHServer-Setup-$version.exe"
$hash = (Get-FileHash $setup -Algorithm SHA256).Hash
"$hash  $(Split-Path -Leaf $setup)" | Set-Content "$setup.sha256"
Write-Host "Done: $setup  (SHA256 $hash)"
