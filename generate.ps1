Param(
    [Parameter(Mandatory=$False)]
    [switch]$UpdateTools
)

# PowerShell <3.0 compatibility
if ($PSScriptRoot -like "") {
    $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

$update=""
if ($UpdateTools) {
    $update="-u"
}

Push-Location $PSScriptRoot

go mod tidy
go mod vendor

go get -v $update github.com/abice/go-enum
go get -v $update github.com/vektra/mockery/v2/.../
go mod tidy

# TODO: Remove all old mocks

go generate ./...

Pop-Location