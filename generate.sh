#!/bin/bash

cd $(dirname "$0") || exit 1

if [[ "$1" == "-u" ]]; then
    GOPATH=${GOPATH:-$HOME/go}
    GOBIN=$GOPATH/bin

    tmpdir=$(mktemp -d)
    pushd "$tmpdir" || exit $?

    latestDownloadURL_mockery=$(curl -s https://api.github.com/repos/vektra/mockery/releases/latest | \
                                jq -r '.assets[] | select(.name | contains("Linux_x86_64")) | .browser_download_url')
    wget "$latestDownloadURL_mockery" || exit $?
    tar -xf *.tar.gz || exit $?
    chmod +x mockery || exit $?
    cp mockery "$GOBIN" || exit $?

    rm -rf *

    latestDownloadURL_goenum=$(curl -s https://api.github.com/repos/abice/go-enum/releases/latest | \
                               jq -r '.assets[] | select(.name | contains("Linux_x86_64")) | .browser_download_url')
    wget "$latestDownloadURL_goenum" || exit $?
    cp go-enum_Linux_x86_64 "$GOBIN/go-enum" || exit $?
    chmod +x "$GOBIN/go-enum" || exit $?

    popd || exit $?
    rm -rf "$tmpdir"
fi

find . -name 'mock_*_test.go' -type f -delete

go generate ./...
