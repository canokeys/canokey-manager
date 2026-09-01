#!/bin/bash
# Script to produce an OS X installer .pkg

set -e

CWD=`pwd`
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
SOURCE_DIR="$CWD/ckman"
RELEASE_VERSION=`$SOURCE_DIR/ckman --version | awk '{print $(NF)}'`

if [ -z "$1" ]
then
	PKG="ckman.pkg"
else
	PKG="$1"
fi

echo "Release version : $RELEASE_VERSION"
echo "Binaries: $SOURCE_DIR"

set -x

cd $SCRIPT_DIR

# Ensure executable, since we may have unpacked from zip
chmod +x pkg_scripts/*

mkdir -p pkg/root/usr/local/bin pkg/comp
cp -R $SOURCE_DIR pkg/root/usr/local/

# Create a symlink to the main binary that is on the PATH
(cd pkg/root/usr/local/bin && ln -s ../ckman/ckman)

pkgbuild --root="pkg/root" --scripts="pkg_scripts" --identifier "org.canokeys.canokey-manager" --version "$RELEASE_VERSION" "pkg/comp/ckman.pkg"

productbuild  --package-path "pkg/comp" --distribution "distribution.xml" "$PKG"

# Move to dist
mv $PKG $CWD/$PKG

# Clean up
rm -rf pkg
