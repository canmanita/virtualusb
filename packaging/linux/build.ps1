# Builds the Linux packages (dist\vhserver_<version>_all.deb and dist\vhserver-<version>-linux.tar.gz) inside WSL.
# Run from the project root:  powershell -ExecutionPolicy Bypass -File packaging\linux\build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$wslRoot = (wsl -d Ubuntu -- wslpath -a "$root").Trim()
if (-not $wslRoot) { throw "WSL Ubuntu is required to build the Linux packages" }

# Windows editors may leave CRLF line endings in the shell scripts, which bash rejects: normalise them first.
wsl -d Ubuntu -u root -- bash -c "cd '$wslRoot/packaging/linux' && sed -i 's/\r$//' *.sh postinst prerm postrm && cd '$wslRoot' && bash packaging/linux/build-deb.sh && bash packaging/linux/build-tar.sh"
if ($LASTEXITCODE -ne 0) { throw "Linux package build failed" }
Get-ChildItem "$root\dist" -Filter "vhserver*" | Select-Object Name, Length
