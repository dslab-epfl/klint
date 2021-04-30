#!/bin/sh
# $1: path to NF folder

tofrac()
{
  echo "scale=2; $1 / 1000" | bc
}

summarize()
{
  tput="$(tofrac $(cat "$1/throughput"))"
  printf '%s\t' "$tput"

  lines="$(cat "$1/latencies/1000" | wc -l)"
  num50="$(echo "$lines / 2 + 1" | bc)"
  num99="$(echo "$lines * 0.99 / 1" | bc)"
  for n in $(cat "$1/latencies/1000" | sort -n | sed "$num50"'p;'"$num99"'q;d' | tr '\n' ' '); do
    printf '%s\t' "$(tofrac "$n")"
  done
}

printf "\tVigor\t\t\tKlint\n"
printf "\tTput\tLat50\tLat99\tTput\tLat50\tLat99\n"
for nf in bridge firewall maglev nat policer; do
  vignf="$nf"
  if [ "$nf" = 'firewall' ]; then vignf='fw'; fi
  if [ "$nf" = 'maglev' ]; then vignf='lb'; fi
  if [ "$nf" = 'policer' ]; then vignf='pol'; fi
  displaynf="$nf"
  if [ "$nf" = 'firewall' ]; then displaynf='fire.'; fi # too long otherwise
  printf "$displaynf\t$(summarize "results/singledir-vigor-$vignf")$(summarize "results/singledir-ours-$nf")\n"
done
printf "\nTput is in Gb/s, lat in us\n\n"
