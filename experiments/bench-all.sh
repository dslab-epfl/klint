#!/bin/sh
# TODO: document need for musl-gcc somewhere

exp_dir=$(pwd)
rm -rf "$exp_dir/results"
mkdir "$exp_dir/results"

cd "$exp_dir/../benchmarking"

# Bridge comparison
bench_bridge()
{
  echo '[!!!] Benchmarking Bridge: '"$2"
  while ! ./bench.sh $1 standard 2 ; do
    sleep 5
  done
  mv 'results' "$exp_dir/results/bridge-$2"
}
NF=bridge bench_bridge "$exp_dir/baselines/fastclick" 'click'
NF=bridge OS=dpdk NET=dpdk BATCH_SIZE=32 bench_bridge '..' 'dpdk'
NF=bridge NF_EXT=.o CC=musl-gcc OS=linux NET=tinynf bench_bridge '..' 'ours'
NF=vigbridge bench_bridge "$exp_dir/baselines/vigor" 'vigor-dpdk'
NF=bridge bench_bridge "$exp_dir/baselines/tinynf" 'vigor-tinynf'

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
