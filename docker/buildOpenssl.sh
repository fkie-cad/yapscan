#!/bin/bash

cd /opt/openssl

BUILD_THREADS=${BUILD_THREADS:-1}

./Configure --prefix=$PWD/dist --cross-compile-prefix=x86_64-w64-mingw32- no-idea no-mdc2 no-rc5 shared mingw64 || exit $?
make -j$BUILD_THREADS || exit $?
mkdir -p dist/bin dist/include dist/lib
make install || exit 0