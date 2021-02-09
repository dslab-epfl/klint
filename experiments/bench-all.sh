#!/bin/sh

exp_dir=$(pwd)
rm -rf "$exp_dir/results/"
cd "$exp_dir/../benchmarking"

for net in tinynf dpdk; do
  os_choices='linux'
  if [ "$net" = 'dpdk' ]; then os_choices='linux dpdk'; fi

  batch_choices='1'
  if [ "$net" = 'dpdk' ]; then batch_choices='1 32'; fi

  for os in $os_choices; do
    for batch in $batch_choices; do
      mkdir -p "$exp_dir/results/$os-$net-$batch/"

      for nf in vigor-nat vigor-bridge vigor-policer vigor-firewall nop; do
        layer=4
        if [ "$nf" = 'vigor-bridge' ]; then layer=2; fi
        if [ "$nf" = 'vigor-policer' ]; then layer=3; fi

        echo '[!!!] Benchmarking: '"$nf on $os-$net-$batch"
        while ! BATCH_SIZE=$batch NET=$net OS=$os NF=$nf ./bench.sh .. --latencyload=-1 standard $layer ; do
          echo '[!!!] Retrying after 5s...'
          sleep 5
        done

        cp -r 'results' "$exp_dir/results/$os-$net-$batch/$nf"
        cp 'bench.log' "$exp_dir/results/$os-$net-$batch/$nf/bench.log"
      done
    done
  done
done
