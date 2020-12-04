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


cores=`cat /proc/cpuinfo | grep "cpu cores" | head -n1 | cut -d: -f2 | cut -d' ' -f2`
cores=$((cores*2))

./prepare.sh

mkdir -p build/ &>/dev/null

OPENSSL_VERSION=${OPENSSL_VERSION:-OpenSSL_1_1_1-stable}
YARA_VERSION=${YARA_VERSION:-v4.0.2}

docker build \
    --build-arg BUILD_THREADS=$cores \
    --build-arg OPENSSL_VERSION=$OPENSSL_VERSION --build-arg YARA_VERSION=$YARA_VERSION \
    --network=host -t yapscan-xcompile -f Dockerfile.xwin .

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

if [[ "$buildYapscan" == "1" ]]; then
    export CGO_CFLAGS="-I/opt/yara/libyara/include \$(pkg-config --static --cflags openssl)"
    export CGO_LDFLAGS="-L/opt/yara/libyara/.libs -lyara -static \$(pkg-config --static --libs openssl)"

    pushd yapscan/cmd/yapscan
    go build -trimpath -o /opt/yapscan/build/yapscan.exe -tags yara_no_pkg_config
    popd &>/dev/null
fi

if [[ "$buildYapscanDll" == "1" ]]; then
    export CGO_CFLAGS="-I/opt/yara/libyara/include \$(pkg-config --static --cflags openssl) -fvisibility=hidden"
    export CGO_LDFLAGS="-L/opt/yara/libyara/.libs -lyara -static \$(pkg-config --static --libs openssl)"

    pushd yapscan/cmd/yapscan-dll
    go build -trimpath -o /opt/yapscan/build/yapscan.dll -tags yara_no_pkg_config -buildmode=c-shared
    popd &>/dev/null
fi

EOF
