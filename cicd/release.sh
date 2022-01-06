#!/bin/bash

zstd_level=12

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

repo="fkie-cad/yapscan"

wd=$(pwd)
tmpdir=$(mktemp -d)

if [[ ! "$tmpdir" || ! -d "$tmpdir" ]]; then
    echo "ERROR: Could not create temporary directory"
    exit 10
fi

runId=$(gh run list -q '.[] | select(.headBranch == "master")' --json headBranch,conclusion,databaseId -L1 | jq '.databaseId')
gh -R $repo run download -D "$tmpdir" $runId || exit 11

pushd "$tmpdir" || exit 11

mkdir yapscan_linux_amd64 yapscan_windows_amd64

pushd yapscan_linux_amd64 || exit 11
mv ../deps-linux/* . || exit 12
mv ../yapscan-linux/* . || exit 13
chmod +x yapscan
popd || exit 11

pushd yapscan_windows_amd64 || exit 11
mv ../yapscan-windows/* . || exit 13
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
echo "Creating release draft $RELEASE_TAG and uploading assets..."

gh -R $repo release create -d $RELEASE_TAG \
    "yapscan_linux_amd64.zip" \
    "yapscan_linux_amd64.tar.zst" \
    "yapscan_windows_amd64.zip" \
    "yapscan_windows_amd64.tar.zst" || exit 15

echo "Done"
