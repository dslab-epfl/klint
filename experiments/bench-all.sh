#!/bin/sh
# TODO: document need for musl-gcc somewhere

exp_dir=$(pwd)
rm -rf "$exp_dir/results"
mkdir "$exp_dir/results"

cd "$exp_dir/../benchmarking"

# Bridge comparison
bridge_args='standard 2'
echo '[!!!] Benchmarking bridges'
while ! NF=bridge BATCH_SIZE=32 ./bench.sh "$exp_dir/baselines/fastclick" $bridge_args ; do sleep 5; done
mv 'results' "$exp_dir/results/bridge-click"
while ! NF=bridge OS=dpdk NET=dpdk BATCH_SIZE=32 ./bench.sh '..' $bridge_args ; do sleep 5; done
mv 'results' "$exp_dir/results/bridge-dpdk"
while ! NF=bridge NF_EXT=.o CC=musl-gcc OS=linux NET=tinynf ./bench.sh '..' $bridge_args ; do sleep 5; done
mv 'results' "$exp_dir/results/bridge-ours"
while ! NF=vigbridge ./bench.sh "$exp_dir/baselines/vigor" $bridge_args ; do sleep 5; done
mv 'results' "$exp_dir/results/bridge-vigor-dpdk"
while ! NF=bridge ./bench.sh "$exp_dir/baselines/tinynf" $bridge_args ; do sleep 5; done
mv 'results' "$exp_dir/results/bridge-vigor-tinynf"

# Comparison of our NFs vs Vigor-TinyNF ones
singledir_args='--acceptableloss=0.001 --latencyload=1000 standard-single'
for nf in bridge firewall maglev nat policer; do
  layer=2
  if [ "$nf" = 'maglev' ] || [ "$nf" = 'policer' ]; then layer=3; fi
  if [ "$nf" = 'firewall' ] || [ "$nf" = 'nat' ]; then layer=4; fi

  extra_arg=''
  if [ "$nf" = 'maglev' ]; then extra_arg='--maglev'; fi

  echo '[!!!] Benchmarking our NF: '"$nf"
  while ! NF_EXT=.o CC=musl-gcc NF=$nf OS=linux NET=tinynf ./bench.sh '..' $extra_arg $singledir_args $layer ; do
    sleep 5
  done
  mv 'results' "$exp_dir/results/singledir-ours-$nf"
done
for nf in bridge fw lb nat pol; do
  layer=2
  if [ "$nf" = 'lb' ] || [ "$nf" = 'pol' ]; then layer=4; fi
  if [ "$nf" = 'fw' ] || [ "$nf" = 'nat' ]; then layer=4; fi

  extra_arg=''
  if [ "$nf" = 'lb' ]; then extra_arg='--maglev'; fi

  echo '[!!!] Benchmarking Vigor-on-TinyNF NF: '"$nf"
  while ! NF=$nf ./bench.sh "$exp_dir/baselines/tinynf" $extra_arg $singledir_args $layer ; do
    sleep 5
  done
  mv 'results' "$exp_dir/results/singledir-vigor-$nf"
done
