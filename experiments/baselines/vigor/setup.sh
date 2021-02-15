#!/bin/bash
set -eux

DIR="$(pwd)"
DPDK_VER='20.08'

cd dpdk
  if [ ! -f '.version' ] || [ "$(cat .version)" != "$DPDK_VER" ]; then
    git reset --hard HEAD
    git clean -xfd

    for p in "$DIR/vigor/setup/"dpdk.*.patch; do
      patch -p1 < "$p"
    done

    make install -j$(nproc) T=x86_64-native-linuxapp-gcc DESTDIR=. MAKE_PAUSE=n

    echo "$DPDK_VER" > '.version'
  fi
cd -
