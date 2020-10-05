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
CONFIG_FILENAME="$config" make --no-print-directory -C ../../config

# OS (must be last)
NF=$(basename $(pwd)) make --no-print-directory -C ../../os

# Run
taskset -c 6 sudo ../../os/build/app/nf
