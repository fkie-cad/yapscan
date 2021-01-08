# PowerShell <3.0 compatibility
if ($PSScriptRoot -like "") {
    $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

Push-Location $PSScriptRoot

go mod tidy
go mod vendor

go get -v -u github.com/abice/go-enum
go get -v -u github.com/vektra/mockery/v2/.../
go mod tidy

go generate ./...

Pop-Location