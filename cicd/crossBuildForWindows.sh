#!/bin/bash

# This script reads the following environment variables for optional configuration.
# OPENSSL_VERSION
# YARA_VERSION
# GO_VERSION

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
cicd="$(realpath "$cicd")"
cd "$cicd" || exit $?

mkdir -p build/ &>/dev/null

_default_OPENSSL_VERSION=$("$cicd/opensslVersion.sh") || exit $?
_default_YARA_VERSION=$("$cicd/yaraVersion.sh") || exit $?

OPENSSL_VERSION=${OPENSSL_VERSION:-$_default_OPENSSL_VERSION}
YARA_VERSION=${YARA_VERSION:-$_default_YARA_VERSION}

if [[ "$GO_VERSION" == "" ]]; then
    GO_IMAGE="golang:buster"
else
    GO_IMAGE="golang:${GO_VERSION}-buster"
fi

dockerBuildExtraArgs=""
if [[ "$pull" == "1" ]]; then
    dockerBuildExtraArgs="--pull"
fi

docker build \
    $dockerBuildExtraArgs \
    --build-arg GO_IMAGE=$GO_IMAGE \
    --build-arg BUILD_THREADS=$cores \
    --build-arg OPENSSL_VERSION=$OPENSSL_VERSION --build-arg YARA_VERSION=$YARA_VERSION \
    --network=host -t yapscan-xcompile -f Dockerfile.xwin . || exit $?

docker run --rm --network=host --user "$(id -u):$(id -g)" --volume "$cicd/..:/opt/yapscan" -i yapscan-xcompile <<EOF
export PKG_CONFIG_LIBDIR=/opt/yapscan-deps/lib/pkgconfig

export CC=x86_64-w64-mingw32-gcc
export LD=x86_64-w64-mingw32-ld
export CGO_ENABLED=1
export GOOS=windows
export GOCACHE=/opt/yapscan/cicd/.build-cache/go
export GOMODCACHE=/opt/yapscan/cicd/.build-cache/mod

if [[ "$buildMemtest" == "1" ]]; then
    pushd yapscan/cmd/memtest || exit \$?
    go build -trimpath -o /opt/yapscan/cicd/build/memtest.exe -tags yara_static -buildmode=exe || exit \$?
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
