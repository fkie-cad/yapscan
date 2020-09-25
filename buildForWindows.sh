#!/bin/bash

if [[ "$#" == "0" ]]; then
    # Build all by default
    buildYapscan=1
    buildMemtest=1
else
    # Build depends on arguments
    buildYapscan=0
    buildMemtest=0
fi

for arg in "$@"; do
    case "$arg" in
    yapscan)
        buildYapscan=1
        ;;
    memtest)
        buildMemtest=1
        ;;
    all)
        buildYapscan=1
        buildMemtest=1
        ;;
    *)
        echo "Invalid build target \"$arg\"!"
        exit 1
        ;;
    esac
done


cores=`cat /proc/cpuinfo | grep "cpu cores" | head -n1 | cut -d: -f2 | cut -d' ' -f2`
cores=$((cores*2))

go mod tidy
go mod vendor

go get github.com/abice/go-enum
go mod tidy

go generate ./...
mkdir -p build/ &>/dev/null

docker build --build-arg BUILD_THREADS=$cores --network=host -t yapscan-xcompile -f Dockerfile.xwin .

docker run --rm --network=host --volume $(pwd):/opt/yapscan -i yapscan-xcompile <<EOF
export PKG_CONFIG_LIBDIR=/opt/openssl/dist/lib/pkgconfig

export CC=x86_64-w64-mingw32-gcc
export LD=x86_64-w64-mingw32-ld
export CGO_ENABLED=1
export GOOS=windows

if [[ "$buildMemtest" == "1" ]]; then
    pushd yapscan/cmd/memtest
    go build -trimpath -o /opt/yapscan/build/memtest.exe
    popd &>/dev/null
fi

export CGO_CFLAGS="-I/opt/yara/libyara/include \$(pkg-config --static --cflags openssl)"
export CGO_LDFLAGS="-L/opt/yara/libyara/.libs -lyara -static \$(pkg-config --static --libs openssl)"

if [[ "$buildYapscan" == "1" ]]; then
    pushd yapscan/cmd/yapscan
    go build -trimpath -o /opt/yapscan/build/yapscan.exe -tags yara_no_pkg_config
    popd &>/dev/null
fi
EOF