#!/bin/bash

go mod tidy
go mod vendor

go get github.com/abice/go-enum
go mod tidy

go generate ./...
mkdir -p build/ &>/dev/null

docker build --network=host -t yapscan-xcompile -f Dockerfile.xwin .

docker run --rm --network=host --volume $(pwd):/opt/yapscan -i yapscan-xcompile <<EOF
export CC=x86_64-w64-mingw32-gcc
export LD=x86_64-w64-mingw32-ld
export CGO_ENABLED=1
export GOOS=windows
export CGO_CFLAGS="-I/opt/yara/libyara/include"
export CGO_LDFLAGS="-L/opt/yara/libyara/.libs -lyara -static"

cd yapscan/cmd/yapscan
go build -o /opt/yapscan/build/yapscan.exe -tags yara_no_pkg_config
EOF