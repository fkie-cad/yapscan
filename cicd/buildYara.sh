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

./bootstrap.sh
if [[ "$buildEnv" == "docker" ]]; then
    ./configure CPPFLAGS="$(pkg-config --static --cflags openssl)" LDFLAGS="$(pkg-config --static --libs openssl)" \
            "$installPrefix" \
            --host=x86_64-w64-mingw32 \
            --disable-shared \
            --with-crypto || exit $? # --with-cuckoo --with-magic --with-dotnet
elif [[ "$buildEnv" == "mingw" ]]; then
    ./configure CPPFLAGS="$(pkg-config --static --cflags openssl)" LDFLAGS="$(pkg-config --static --libs openssl)" \
            "$installPrefix" \
            --disable-shared \
            --with-crypto || exit $? # --with-cuckoo --with-magic --with-dotnet
fi

make -j$BUILD_THREADS || exit $?
make install || exit $?
