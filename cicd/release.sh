#!/bin/bash

zstd_level=12

if [[ "$GITHUB_USERNAME" == "" || "$GITHUB_TOKEN" == "" ]]; then
    echo "ERROR: Missing GITHUB_USERNAME or GITHUB_TOKEN environment variables."
    exit 1
fi

while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    -r|--create-release)
      CREATE_RELEASE=1
      RELEASE_TAG="$2"
      shift # past argument
      shift # past value
      ;;
  esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

function curl-authenticated() {
    curl -u "$GITHUB_USERNAME:$GITHUB_TOKEN" "$@"
}

function githubApi() {
    endpoint="$1"
    shift
    curl-authenticated -H "Accept: application/vnd.github.v3+json" "https://api.github.com/repos/fkie-cad/yapscan$endpoint" "$@"
}

function getDownloadURL() {
    # Assuming the first entry is the latest artifact
    githubApi /actions/artifacts | jq -c '.artifacts[] | {name: .name, url: .archive_download_url}' | grep "$1" | head -n1 | jq -r '.url'
}

function download() {
    url=$(getDownloadURL "$1")
    if [[ "$url" == "" ]]; then
        echo "ERROR: Could not get download url for artifact '$1'."
        exit 1
    fi
    echo "Downloading from $url"
    curl-authenticated -L -o "$1.zip" "$url"
}

wd=$(pwd)
tmpdir=$(mktemp -d)

if [[ ! "$tmpdir" || ! -d "$tmpdir" ]]; then
    echo "ERROR: Could not create temporary directory"
    exit 10
fi

pushd "$tmpdir" || exit 11

download yapscan-linux || exit 12
download deps-linux || exit 12
download yapscan-windows || exit 12

mkdir yapscan_linux_amd64 yapscan_windows_amd64

pushd yapscan_linux_amd64 || exit 11
7z x ../deps-linux.zip || exit 13
7z x ../yapscan-linux.zip || exit 13
chmod +x yapscan
popd || exit 11

pushd yapscan_windows_amd64 || exit 11
7z x ../yapscan-windows.zip || exit 13
chmod +x yapscan.exe
popd || exit 11

rm "$wd/yapscan_linux_amd64.zip" &>/dev/null
7z a "$wd/yapscan_linux_amd64.zip" yapscan_linux_amd64/ || exit 14
rm "$wd/yapscan_linux_amd64.tar.zst" &>/dev/null
tar -cvf - yapscan_linux_amd64/ | zstd -$zstd_level - -o "$wd/yapscan_linux_amd64.tar.zst" || exit 14
rm "$wd/yapscan_windows_amd64.zip" &>/dev/null
7z a "$wd/yapscan_windows_amd64.zip" yapscan_windows_amd64/ || exit 14
rm "$wd/yapscan_windows_amd64.tar.zst" &>/dev/null
tar -cvf - yapscan_windows_amd64/ | zstd -$zstd_level - -o "$wd/yapscan_windows_amd64.tar.zst" || exit 14

popd || exit 11

rm -rf "$tmpdir"

if [[ "$CREATE_RELEASE" != "1" ]]; then
    exit 0
fi

echo
echo "Creating release draft $RELEASE_TAG..."

upload_url=$(githubApi /releases -X POST -d '{"tag_name":"'$RELEASE_TAG'", "draft": true}' | jq -r '.upload_url')
if [[ "$?" != "0" ]]; then
    echo "ERROR: Could not create release!"
    exit 15
fi
upload_url=${upload_url%{*}

echo "Uploading assets to $upload_url..."

curl-authenticated -L -X POST -H "Content-Type: application/octet-stream" \
     --data-binary @"yapscan_linux_amd64.zip" "${upload_url}?name=yapscan_linux_amd64.zip" || exit 16
curl-authenticated -L -X POST -H "Content-Type: application/octet-stream" \
     --data-binary @"yapscan_linux_amd64.tar.zst" "${upload_url}?name=yapscan_linux_amd64.tar.zst" || exit 16
curl-authenticated -L -X POST -H "Content-Type: application/octet-stream" \
     --data-binary @"yapscan_windows_amd64.zip" "${upload_url}?name=yapscan_windows_amd64.zip" || exit 16
curl-authenticated -L -X POST -H "Content-Type: application/octet-stream" \
     --data-binary @"yapscan_windows_amd64.tar.zst" "${upload_url}?name=yapscan_windows_amd64.tar.zst" || exit 16

echo "Done"
