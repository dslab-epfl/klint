#!/bin/sh

# Input: Files to compile
# Optional extra input: environment variable $EXTRA_BPF_CFLAGS for the BPF compilation
# Output, as files in the working directory:
# - 'bpf.obj', the compiled BPF bytecode
# - 'bpf.bin', the kernel-JITed native code
# - 'bpf.calls', a file with one line per called BPF helper, format '[hex kernel address] [name]'
# - 'bpf.maps', a file with one line per BPF map, format '[hex kernel address] [hex data]'

# This script contains many ludicrous things, so let me explain...
# - First, the built-in bpftool in Ubuntu isn't built with libbfd support, so it cannot dump JITted programs
# - Second, the bpftool from the kernel segfaults when loading programs, but works fine for dumping
# (these observations were made on Ubuntu 18.04 HWE, i.e., kernel 5.4)
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

# Prep the headers just right. This is beyond absurd, especially the uapi/linux / linux confusion...
rm -rf '/tmp/bpf-headers'
mkdir '/tmp/bpf-headers'
ln -s "$THIS_DIR/libbpf/src" '/tmp/bpf-headers/bpf'
mkdir -p '/tmp/bpf-headers/uapi/linux'
cp '/usr/include/linux/'* '/tmp/bpf-headers/uapi/linux/.' 2>/dev/null
cp "$THIS_DIR/libbpf/include/uapi/linux/"* '/tmp/bpf-headers/uapi/linux/.'
cp "$THIS_DIR/libbpf/include/linux/"* '/tmp/bpf-headers/uapi/linux/.'
cp -r '/tmp/bpf-headers/uapi/linux/' '/tmp/bpf-headers/linux/'

# Compile (not sure why we explicitly need that x86_64 include but we do)
clang -O3 -target bpf -isystem '/tmp/bpf-headers' -isystem '/usr/include/x86_64-linux-gnu/' \
      $EXTRA_BPF_CFLAGS \
      -D u8=__u8 -D u16=__u16 -D u32=__u32 -D u64=__u64 -D __wsum=__u32 -D __sum16=__u16 \
      -o 'bpf.obj' -c $@
if [ $? -ne 0 ]; then
  # This is ludicrous
  if [ "$(find /usr/include/ -name stubs-32.h)" = '' ]; then
    echo 'WARNING: gnu/stubs-32.h header not found, if compilation failed because of it you need the i386 libc dev packages, e.g. libc6-dev-i386 on Ubuntu'
  fi
  exit 1
fi

# Remove an existing program, just in case some previous script run failed
sudo rm -f '/sys/fs/bpf/temp'

# Load into kernel
sudo bpftool prog load 'bpf.obj' '/sys/fs/bpf/temp'

# Dump BPF as text
sudo "$LINUX_BPFTOOL" prog dump xlated pinned '/sys/fs/bpf/temp' > '/tmp/bpf'

# Dump x86 as text
sudo "$LINUX_BPFTOOL" prog dump jited pinned '/sys/fs/bpf/temp' > '/tmp/x86'

# Create the calls list (address to name)
grep -F call '/tmp/x86' | sed 's/.*\(0x.*\)/\1/' > '/tmp/x86-calls'
grep -F call '/tmp/bpf' | sed 's/.*call \(.*\)#.*/\1/' > '/tmp/bpf-calls'
paste -d ' ' '/tmp/x86-calls' '/tmp/bpf-calls' > 'bpf.calls'

# Create the maps list (address to maps)
# First, create a mapping from addresses to names, using the order in which loads and relocations appear
sed 's/.*movabs $\(0x[0-9a-z]*\),%rdi/\1/;t;d' '/tmp/x86' > '/tmp/map-addrs'
objdump -r 'bpf.obj' | tail -n+6 | tr -s ' ' | cut -d ' ' -f 3 | head -n-2 > '/tmp/map-names'
paste -d ' ' '/tmp/map-addrs' '/tmp/map-names' | sort | uniq > '/tmp/addrs-to-names'
# Then, create a mapping from names to data
MAPS_SECTION_IDX="$(readelf --sections 'bpf.obj' | sed 's/.*\[\s*\([0-9]*\)\]\s*maps.*/\1/;t;d')"
objdump -h 'bpf.obj' | grep '.maps' | awk '{print "dd if='bpf.obj' of='/tmp/maps' bs=1 count=$[0x" $3 "] skip=$[0x" $6 "]"}' | bash 2>/dev/null # From https://stackoverflow.com/a/3925586
readelf -s 'bpf.obj' | tail -n+4 | tr -s ' ' | grep -F "DEFAULT $MAPS_SECTION_IDX" | cut -d ' ' -f 3,9 > '/tmp/offset-to-name'
cat '/tmp/offset-to-name' | awk '{print "echo -n " $2 " ; echo -n '"' '"' ; xxd -p -seek 0x" $1 " -l 20 /tmp/maps"}' | sh > '/tmp/names-to-contents'
# Finally, combine the two
cat '/tmp/addrs-to-names' | awk '{ print "echo " $1 " $(grep -F " $2 " /tmp/names-to-contents | cut -d '"' '"' -f 2)"  }' | sh > 'bpf.maps'

# Dump x86 as binary
sudo "$LINUX_BPFTOOL" prog dump jited pinned '/sys/fs/bpf/temp' file '/tmp/bin'
sudo chmod 644 '/tmp/bin'
cp '/tmp/bin' 'bpf.bin'

# Remove
sudo rm '/sys/fs/bpf/temp'
