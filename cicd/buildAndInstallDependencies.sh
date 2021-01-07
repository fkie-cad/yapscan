#!/bin/bash

DEFAULT_INSTALL_PREFIX=/opt/yapscan-deps

buildEnv=$("$(dirname "$0")/determineBuildEnvironment.sh") || (echo "$buildEnv"; exit 42)

if [[ "$buildEnv" != "mingw" ]]; then
    echo "ERROR: This script is only meant for use with MSYS2 MinGW."
    echo "If you want to use docker to cross compile yapscan for windows, use \"buildForWindows.sh\" instead."
    echo "If you want to build natively build for linux, please manually install OpenSSL and libyara."
    exit 42
fi

function showHelp() {
    echo "Usage: ./buildAndInstallDependencies.sh [--overwrite|-o] <source_dir>"
    echo "    If --overwrite | -o is set, the source directories will be deleted and freshly cloned."
    echo "    <source_dir> is the directory, the source of all dependencies will be cloned into."
    echo "    The dependencies will be install into the prefix given by the INSTALL_PREFIX environment variable, or \"$DEFAULT_INSTALL_PREFIX\" by default."
}

overwrite=0
if [[ "$1" == "--overwrite" || "$1" == "-o" ]]; then
    overwrite=1
    srcDir="$2"
else
    srcDir="$1"
fi

if [[ "$srcDir" == "" ]]; then
    showHelp
    exit 1
fi

mkdir -p "$srcDir" &>/dev/null

if [[ "$overwrite" == "1" ]]; then
    rm -rf "$srcDir/openssl"
    rm -rf "$srcDir/yara"
fi

cicd="$(dirname "$0")"

OPENSSL_VERSION=$("$cicd/opensslVersion.sh") || exit $?
YARA_VERSION=$("$cicd/yaraVersion.sh") || exit $?

INSTALL_PREFIX=${INSTALL_PREFIX:-$DEFAULT_INSTALL_PREFIX}

if [ ! -d "$srcDir/openssl" ]; then
    # openssl dir does not exist
    git clone --depth=1 --branch=$OPENSSL_VERSION https://github.com/openssl/openssl.git "$srcDir/openssl" || exit $?
fi

if [ ! -d "$srcDir/yara" ]; then
    # yara dir does not exist
    git clone --depth=1 --branch=$YARA_VERSION https://github.com/VirusTotal/yara.git "$srcDir/yara" || exit $?
fi

"$cicd/buildOpenssl.sh" "$srcDir/openssl" "$INSTALL_PREFIX" || exit $?

export PKG_CONFIG_LIBDIR="$INSTALL_PREFIX/lib/pkgconfig"
"$cicd/buildYara.sh" "$srcDir/yara" "$INSTALL_PREFIX" || exit $?
