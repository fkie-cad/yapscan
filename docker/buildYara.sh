#!/bin/bash

BUILD_THREADS=${BUILD_THREADS:-1}

export PKG_CONFIG_LIBDIR=/opt/openssl/dist/lib/pkgconfig

cd yara
./bootstrap.sh
./configure CPPFLAGS="`pkg-config --static --cflags openssl`" LDFLAGS="`pkg-config --static --libs openssl`" \
        --host=x86_64-w64-mingw32 \
        --disable-shared \
        --with-crypto || exit $? # --with-cuckoo --with-magic --with-dotnet
make -j$BUILD_THREADS
