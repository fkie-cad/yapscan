#!/bin/bash

export CC=gcc

cd yara
./bootstrap.sh
unset CC
./configure --host=x86_64-w64-mingw32 --disable-shared
make -j4
