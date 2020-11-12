#!/bin/bash

go mod tidy
go mod vendor

go get -v github.com/abice/go-enum
go get -v github.com/vektra/mockery
go mod tidy

go generate ./...