#!/bin/bash

buildYapscan=0
buildYapscanDll=0
buildMemtest=0
pull=0

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
    --pull)
        pull=1
        ;;
    *)
        echo "Invalid build target \"$arg\"!"
        exit 1
        ;;
    esac
done

buildCount=$((buildYapscan+buildYapscanDll+buildMemtest))
if [[ "$buildCount" == "0" ]]; then
    buildYapscan=1
    buildYapscanDll=1
    buildMemtest=1
fi

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

dockerBuildExtraArgs=""
if [[ "$pull" == "1" ]]; then
    dockerBuildExtraArgs="--pull"
fi

docker build \
    $dockerBuildExtraArgs \
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
    pushd yapscan/cmd/memtest || exit \$?
    go build -trimpath -o /opt/yapscan/cicd/build/memtest.exe -buildmode=exe || exit \$?
    popd &>/dev/null || exit \$?
fi

if [[ "$buildYapscan" == "1" ]]; then
    pushd yapscan/cmd/yapscan || exit \$?
    go build -trimpath -o /opt/yapscan/cicd/build/yapscan.exe -tags yara_static -buildmode=exe || exit \$?
    popd &>/dev/null || exit \$?
fi

if [[ "$buildYapscanDll" == "1" ]]; then
    pushd yapscan/cmd/yapscan-dll || exit \$?
    go build -trimpath -o /opt/yapscan/cicd/build/yapscan.dll -tags yara_static -buildmode=c-shared || exit \$?
    popd &>/dev/null || exit \$?
fi

EOF
