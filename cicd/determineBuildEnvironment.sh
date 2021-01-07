#!/bin/bash

# Determine build environment for windows target

sys=$(uname)

if [[ "$sys" == "Linux" ]]; then
    # We are running on Linux => use docker
    echo "docker"
elif [[ "$sys" == "MINGW"* ]]; then
    # MINGW, use that
    echo "mingw"
elif [[ "$sys" == "MSYS"* ]]; then
    # MSYS, error, use mingw instead
    echo "Invalid build environment: $sys! Please use \"MSYS MinGW\" instead!"
    exit 2
else
    # unknown environment
    echo "Unknown build environment: $sys"
    exit 1
fi
