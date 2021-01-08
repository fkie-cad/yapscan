#!/bin/bash

cd $(dirname "$0") || exit 1

update=""
if [[ "$1" == "-u" ]]; then
    update="-u"
fi

go mod tidy
go mod vendor

go get -v $update github.com/abice/go-enum
go get -v $update github.com/vektra/mockery/v2/.../
go mod tidy

go generate ./...