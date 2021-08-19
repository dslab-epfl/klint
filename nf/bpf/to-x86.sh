#!/bin/bash

# This script contains many ludicrous things, so let me explain...
# - First, the built-in bpftool in Ubuntu isn't built with libbfd support, so it cannot dump JITted programs
# - Second, the bpftool from the kernel segfaults when loading programs, but works fine for dumping
# -> We use both!
# - Third, the location of headers when compiling BPF programs is super weird
# -> We create a folder in /tmp that we then use as -isystem

THIS_DIR="$(dirname $(readlink -f $0))"

LINUX_BPFTOOL='/tmp/linux/tools/bpf/bpftool/bpftool'
if [ ! -f "$LINUX_BPFTOOL" ]; then
  if [ ! -f '/usr/lib/x86_64-linux-gnu/libbfd.so' ]; then
    echo 'libbfd not found, and bpftool needs it to dump programs. Please install it, e.g. binutils-dev in Ubuntu.'
    exit 1
  fi
  echo 'Cloning Linux to build bpftool... will take a bit...'
  git clone --depth=1 'https://github.com/torvalds/linux' /tmp/linux
  make -C '/tmp/linux/tools/bpf/bpftool/'
fi

if [ "$(which bpftool)" = '' ]; then
  echo 'bpftool not found, please install it, e.g. linux-tools-generic on Ubuntu'
  exit 1
fi
bpftool 2>/dev/null
if [ $? -ne 0 ]; then
  echo 'bpftool found but not working, maybe you have the wrong version compared to your kernel, perhaps because you need to reboot to apply a newer one?'
  exit 1
fi

# Ensure we have clang
if [ "$(which clang)" = '' ]; then
  echo 'clang not found. Please install it.'
  exit 1
fi

# Ensure kernel BPF JIT is enabled
echo 1 | sudo tee '/proc/sys/net/core/bpf_jit_enable' >/dev/null

# Ensure the libbpf submodule was cloned
git submodule update --init --recursive

# Prep the headers just right. This is beyond absurd...
rm -rf '/tmp/bpf-headers'
mkdir '/tmp/bpf-headers'
ln -s "$THIS_DIR/libbpf/src" '/tmp/bpf-headers/bpf'
mkdir '/tmp/bpf-headers/uapi'
ln -s "$THIS_DIR/libbpf/include/uapi/linux" '/tmp/bpf-headers/uapi/linux'

# Compile (not sure why we explicitly need that x86_64 include but we do)
# 2nd line is for bridge
# 3rd line is for CRAB
# 4th line is for firewall
# TODO move those to a makefile or smth
#         --include=stdint.h -D u8=uint8_t -D u16=uint16_t -D u32=uint32_t -D u64=uint64_t \
clang -O3 -target bpf -isystem '/tmp/bpf-headers' -isystem '/usr/include/x86_64-linux-gnu/' \
         -isystem . \
         -I common -Wno-compare-distinct-pointer-types \
         -D ntohs=__builtin_bswap16 -D uint64_t=__u64 --include=linux/udp.h \
         -D u8=__u8 -D u16=__u16 -D u32=__u32 -D u64=__u64 \
         -o bpf.o -c $@
if [ $? -ne 0 ]; then
  # This is ludicrous
  if [ "$(find /usr/include/ -name stubs-32.h)" = '' ]; then
    echo 'WARNING: gnu/stubs-32.h header not found, if compilation failed because of it you need the i386 libc dev packages, e.g. libc6-dev-i386 on Ubuntu'
  fi
  exit 1
fi

# Load into kernel
sudo bpftool prog load bpf.o '/sys/fs/bpf/temp'

# Dump
sudo "$LINUX_BPFTOOL" prog dump jited pinned '/sys/fs/bpf/temp'

# Remove
sudo rm '/sys/fs/bpf/temp'
