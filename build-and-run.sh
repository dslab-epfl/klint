#!/bin/bash
set -e

# NF
make -f ../../Makefile.nf

# Config
config=$(mktemp)
cat > "$config" << 'EOF'
  { "lan device", 0 },
  { "wan device", 1 },
  { "expiration time", 30ull * 1000ull * 1000ull * 1000ull },
  { "max flows", 65536 },
  { "external addr", 0 },
  { "start port", 0 }
EOF

cd os
NF=$(pwd)/../nf/nop NF_CONFIG_FILENAME=$(pwd)/../nf/nop/config OS_CONFIG_FILENAME=$(pwd)/config NET=tinynf make

# Run
taskset -c 6 sudo ../../os/bin
