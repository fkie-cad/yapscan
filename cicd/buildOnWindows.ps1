Param(
    [Parameter(Mandatory=$False)]
    [switch]$BuildDeps,

    [Parameter(Mandatory=$False)]
    [switch]$OverwriteDeps,

    [Parameter(Mandatory=$False)]
    [string]$MsysPath
)

$ENV:INSTALL_PREFIX = "/opt/yapscan-deps"  # Note: This be compatible with $ENV:PKG_CONFIG_PATH in enableMingw.ps1.
$SOURCES_DIR = "/opt/yapscan-src"  # This variable can be set to an arbitrary linux-directory.

# PowerShell <3.0 compatibility
if ($PSScriptRoot -like "") {
    $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

$OverwriteFlag=""
if ($OverwriteDeps) {
    $BuildDeps=$TRUE
    $OverwriteFlag="-o"
}

if ($BuildDeps) {
    echo "Building dependencies..."
    Start -FilePath "$MsysPath\msys2_shell.cmd" -ArgumentList "-mingw64","-no-start","-defterm","-c","`"\`"$PSScriptRoot\buildAndInstallDependencies.sh\`" $OverwriteFlag \`"$SOURCES_DIR\`"; res=`$?; echo Press Enter to exit...; read; exit `$res`"" -Wait
    echo "Done."
}

& "$PSScriptRoot\enableMingw.ps1" -MsysPath "$MsysPath"

New-Item -Path . -Name "build" -ItemType "directory" -Erroraction "silentlycontinue"

echo "Building yapscan..."
Push-Location "$PSScriptRoot\..\cmd\yapscan"

go build -trimpath -tags yara_static -o .\build\yapscan.exe

Pop-Location
echo "Done."

echo "Building yapscan-dll..."
Push-Location "$PSScriptRoot\..\cmd\yapscan-dll"

go build -trimpath -tags yara_static -o .\build\yapscan.dll -buildmode=c-shared

Pop-Location
echo "Done."
