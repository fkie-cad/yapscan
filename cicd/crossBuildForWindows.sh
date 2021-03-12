#!/bin/bash

if [[ "$#" == "0" ]]; then
    # Build all by default
    buildYapscan=1
    buildYapscanDll=1
    buildMemtest=1
else
    # Build depends on arguments
    buildYapscan=0
    buildYapscanDll=0
    buildMemtest=0
fi

for arg in "$@"; do
    case "$arg" in
    yapscan)
        buildYapscan=1
        ;;
    yapscan-dll)
        buildYapscanDll=1
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


cores=$(cat /proc/cpuinfo | grep "cpu cores" | head -n1 | cut -d: -f2 | cut -d' ' -f2)
cores=$((cores*2))

cicd="$(dirname "$0")"
if [[ "$cicd" == "." ]]; then
    # Necessary for docker volume
    cicd="$(pwd)"
fi

mkdir -p build/ &>/dev/null

OPENSSL_VERSION=$("$cicd/opensslVersion.sh") || exit $?
YARA_VERSION=$("$cicd/yaraVersion.sh") || exit $?

docker build \
    --build-arg BUILD_THREADS=$cores \
    --build-arg OPENSSL_VERSION=$OPENSSL_VERSION --build-arg YARA_VERSION=$YARA_VERSION \
    --network=host -t yapscan-xcompile -f Dockerfile.xwin . || exit $?

docker run --rm --network=host --volume "$cicd/..:/opt/yapscan" -i yapscan-xcompile <<EOF
export PKG_CONFIG_LIBDIR=/opt/yapscan-deps/lib/pkgconfig

export CC=x86_64-w64-mingw32-gcc
export LD=x86_64-w64-mingw32-ld
export CGO_ENABLED=1
export GOOS=windows

if [[ "$buildMemtest" == "1" ]]; then
    pushd yapscan/cmd/memtest
    go build -trimpath -o /opt/yapscan/cicd/build/memtest.exe -buildmode=exe
    popd &>/dev/null
fi

if [[ "$buildYapscan" == "1" ]]; then
    pushd yapscan/cmd/yapscan
    go build -trimpath -o /opt/yapscan/cicd/build/yapscan.exe -tags yara_static -buildmode=exe
    popd &>/dev/null
fi

if [[ "$buildYapscanDll" == "1" ]]; then
    pushd yapscan/cmd/yapscan-dll
    go build -trimpath -o /opt/yapscan/cicd/build/yapscan.dll -tags yara_static -buildmode=c-shared
    popd &>/dev/null
fi

EOF
