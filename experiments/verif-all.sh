#!/bin/sh

printf "NF\ttime\t\t\t\t#invs\n"
printf "\tsymbex\tinfer\tverif\ttotal\n"
for nf in bridge firewall maglev nat policer router; do
  if [ "$nf" = 'firewall' ]; then
    # too big a name for a tab, don't shift the entire table
    printf 'fw\t'
  else
    printf '%s\t' "$nf"
  fi
  # klint prints the stats at the end, as '#invs infer symbex verif' (because alphabetically ordered)
  make -C "../nf/$nf" -f '../Makefile.nf' >/dev/null
  ../tool/klint.py libnf "../nf/$nf/libnf.so" "../nf/$nf/spec.py" | tail -n 1 | awk '{print $3 "\t" $2 "\t" $4 "\t" ($2+$3+$4) "\t" $1}'
done
