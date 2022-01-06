#!/bin/bash

cd $(dirname "$0") || exit 1

if [[ "$1" == "-u" ]]; then
    go install github.com/abice/go-enum@latest
    go install github.com/vektra/mockery/v2@latest
fi

find . -name 'mock_*_test.go' -type f -delete

go generate ./...
