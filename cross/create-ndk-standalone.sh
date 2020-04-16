#! /bin/bash

# based on https://github.com/Terrahop/react-native-rust-demo

set -euo pipefail

if [ -d NDK ]; then
    printf '\e[33;1mStandalone NDK already exists... Delete the NDK folder to make a new one.\e[0m\n\n'
    printf '$ rm -rf NDK\n'
    exit 0
fi

MAKER="$NDK_HOME/build/tools/make_standalone_toolchain.py"
echo 'Creating standalone NDK...'

mkdir NDK
cd NDK

for ARCH in arm64 arm x86 x86_64; do
    echo "($ARCH)..."
    "$MAKER" --arch $ARCH --api 21 --install-dir $ARCH
done

echo 'Updating .cargo/config.toml...'

cd ..
mkdir -p .cargo
sed 's|$PWD|'"${PWD}"'|g' cargo-config.toml.template > .cargo/config
mv .cargo ..
