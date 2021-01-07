#!/bin/bash

function showHelp() {
    echo "Usage: ./buildOpenssl.sh <sourceDir> [installPrefix]"
}

buildEnv=$("$(dirname "$0")/determineBuildEnvironment.sh") || (echo "$buildEnv"; exit 42)

sourceDir="$1"
if [[ "$sourceDir" == "" ]]; then
    showHelp
    exit 1
fi
installPrefix="$2"
if [[ "$installPrefix" != "" ]]; then
    installPrefix="--prefix=$installPrefix"
fi

cd "$sourceDir" || exit 2

# By default use only one thread
BUILD_THREADS=${BUILD_THREADS:-1}

if [[ "$buildEnv" == "docker" ]]; then
    ./Configure "$installPrefix" --cross-compile-prefix=x86_64-w64-mingw32- no-idea no-mdc2 no-rc5 shared mingw64 || exit $?
elif [[ "$buildEnv" == "msys" ]]; then
    ./Configure "$installPrefix" no-idea no-mdc2 no-rc5 shared mingw64 || exit $?
fi

make -j$BUILD_THREADS || exit $?
make install_dev || exit $?
