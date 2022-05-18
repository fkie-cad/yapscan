#!/bin/bash

targetDir="$1"

if [[ "$targetDir" == "" ]]; then
    echo "Usage: $0 <targetDir>"
    exit 1
fi

tmpdir=$(mktemp -d)

function cleanup() {
    rm -rf "$tmpdir"
    exit 254
}

trap cleanup INT

pushd "$tmpdir" || exit $?
python3 -m venv venv || exit $?
python -m ensurepip || exit $?
python -m pip install json-schema-for-humans || exit $?
popd || exit $?

pushd "$targetDir" || exit $?
generate-schema-doc . || exit $?
popd || exit $?
