#!/bin/bash

cd $(dirname "$0") || exit 1

go mod tidy
go mod vendor

go get -v github.com/abice/go-enum
go get github.com/vektra/mockery/v2/.../
go mod tidy

go generate ./...