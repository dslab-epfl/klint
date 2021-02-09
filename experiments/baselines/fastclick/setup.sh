# in DPDK
make install -j$(nproc) T=x86_64-native-linuxapp-gcc DESTDIR=. MAKE_PAUSE=n

# Fastclick: "Light" config as per the README
# Last line added: no AVX2 for compat, EtherSwitch and auto-batch for the bridge
# TODO: e.g. gcc -march=native -dM -E - < /dev/null | grep -q 'AVX2'
#       to tell whether to pass --disable-avx2
RTE_SDK=$(pwd)/../dpdk RTE_TARGET=x86_64-native-linuxapp-gcc \
  ./configure --enable-dpdk --enable-intel-cpu --verbose --enable-select=poll \
  CFLAGS="-O3" CXXFLAGS="-std=c++11 -O3"  --disable-dynamic-linking --enable-poll \
  --enable-bound-port-transfer --enable-local --enable-flow --disable-task-stats \
  --disable-cpu-load --enable-dpdk-packet --disable-clone --disable-dpdk-softqueue \
  --disable-avx2 --enable-etherswitch --enable-auto-batch
RTE_SDK=$(pwd)/../dpdk RTE_TARGET=x86_64-native-linuxapp-gcc make
