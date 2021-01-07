Param(
    [Parameter(Mandatory=$False)]
    [switch]$BuildDeps,

    [Parameter(Mandatory=$False)]
    [switch]$OverwriteDeps,

    [Parameter(Mandatory=$True)]
    [string]$MsysPath
)

$ENV:INSTALL_PREFIX = "/opt/yapscan-deps"  # Note: This be compatible with $ENV:PKG_CONFIG_PATH below.
$SOURCES_DIR = "/opt/yapscan-src"  # This variable can be set to an arbitrary linux-directory.

$OverwriteFlag=""
if ($OverwriteDeps) {
    $BuildDeps=$TRUE
    $OverwriteFlag="-o"
}

if ($BuildDeps) {
    Start -FilePath "$MsysPath\msys2_shell.cmd" -ArgumentList "-mingw64","-c","`"\`"$PSScriptRoot\buildAndInstallDependencies.sh\`" $OverwriteFlag `"$SOURCES_DIR`"; echo Press Enter to exit.`"; read" -Wait
}

$ENV:PKG_CONFIG_PATH = "$MsysPath\opt\yapscan-deps\lib"
$ENV:PATH += ";$MsysPath\mingw64\bin"

New-Item -Path . -Name "build" -ItemType "directory"

echo "Building yapscan..."
cd "$PSScriptRoot\..\cmd\yapscan"

go build -trimpath -tags yara_static -o .\build\yapscan.exe

echo "Building yapscan-dll..."
cd "$PSScriptRoot\..\cmd\yapscan-dll"

go build -trimpath -tags yara_static -o .\build\yapscan.dll -buildmode=c-shared
