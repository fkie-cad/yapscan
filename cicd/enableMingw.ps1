Param(
    [Parameter(Mandatory=$False)]
    [string]$MsysPath
)

if ($MsysPath -like "") {
    # Try to detect msys
    if (Test-Path "C:\msys64") {
        $MsysPath = "C:\msys64"
    } else {
        echo "ERROR: Could not find MSYS2, please specify via `"-MsysPath <path>`""
        Exit 1
    }
}

$ENV:PKG_CONFIG_PATH = "$MsysPath\opt\yapscan-deps\lib\pkgconfig"
$ENV:PATH += ";$MsysPath\mingw64\bin"

# This should theoretically not be needed, as pkg-config is supposed to handle this.
# However, on my test-system this was needed although `pkg-config --libs yara` did report
# the correct flags: `-LC:\msys64\opt\yapscan-deps\lib -lyara`
$ENV:CGO_LDFLAGS="-L$MsysPath\opt\yapscan-deps\lib"
