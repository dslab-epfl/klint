#!/bin/sh

this_dir=$(pwd)

cd $this_dir/../benchmarking

NF=bridge ./bench.sh ../experiments/baselines/fastclick/ standard 2
cp -r results $this_dir/bridge-click

NF=vigor-bridge BATCH_SIZE=32 OS=dpdk NET=dpdk ./bench.sh .. standard 2
cp -r results $this_dir/bridge-dpdk

NF=vigor-bridge OS=linux NET=tinynf ./bench.sh .. standard 2
cp -r results $this_dir/bridge-tinynf
