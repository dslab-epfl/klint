#!/bin/sh

exp_dir=$(pwd)
rm -rf "$exp_dir/results"
mkdir "$exp_dir/results"

cd "$exp_dir/../benchmarking"

# Comparison of our NFs vs Vigor-TinyNF ones
singledir_args='--acceptableloss=0.001 --latencyload=1000 standard-single'
for nf in bridge firewall maglev nat policer; do
  layer=2
  if [ "$nf" = 'maglev' ] || [ "$nf" = 'policer' ]; then layer=3; fi
  if [ "$nf" = 'firewall' ] || [ "$nf" = 'nat' ]; then layer=4; fi

  extra_arg=''
  if [ "$nf" = 'maglev' ]; then extra_arg='-r'; fi # reverse heatup, i.e., make it think there are backends

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
  if [ "$nf" = 'lb' ]; then extra_arg='-r'; fi # reverse heatup

  echo '[!!!] Benchmarking Vigor-on-TinyNF NF: '"$nf"
  while ! NF=$nf ./bench.sh "$exp_dir/baselines/tinynf" $extra_arg $singledir_args $layer ; do
    sleep 5
  done
  mv 'results' "$exp_dir/results/singledir-vigor-$nf"
done

# Bridge comparison
bench_bridge()
{
  echo '[!!!] Benchmarking Bridge: '"$3"
  while ! $1 ./bench.sh $2 standard 2 ; do
    sleep 5
  done
  mv 'results' "$exp_dir/results/bridge-$3"
}
bench_bridge 'NF=bridge' "$exp_dir/baselines/fastclick" 'click'
bench_bridge 'NF=bridge BATCH_SIZE=32 OS=dpdk NET=dpdk' '..' 'dpdk'
bench_bridge 'NF=bridge OS=linux NET=tinynf' '..' 'ours'
bench_bridge 'NF=vigbridge' "$exp_dir/baselines/vigor" 'vigor-dpdk'
bench_bridge 'NF=bridge' "$exp_dir/baselines/tinynf" 'vigor-tinynf'
