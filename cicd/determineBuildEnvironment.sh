#!/bin/bash

# Determine build environment for windows target

sys=$(uname)

if [[ "$sys" == "Linux" ]]; then
    # We are running on Linux => use docker
    echo "docker"
elif [[ "$sys" == "MSYS"* ]]; then
    # MSYS, use that
    echo "msys"
else
    # unknown environment
    echo "Unknown build environment: $sys"
    exit 1
fi
