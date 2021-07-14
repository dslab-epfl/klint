#!/bin/sh

if [ "$VERIFAST_PATH" = '' ]; then
  echo 'NOTE: Using local VeriFast. If you want to use a custom one, set $VERIFAST_PATH to the root folder of a VeriFast distribution (which contains bin/verifast).'

  if [ ! -d 'verifast' ]; then
    echo 'Local VeriFast not found, downloading...'
    wget 'https://github.com/verifast/verifast/releases/download/21.04/verifast-21.04-linux.tar.gz'
    tar -xf 'verifast-21.04-linux.tar.gz'
    rm 'verifast-21.04-linux.tar.gz'
    mv 'verifast-21.04' 'verifast'
  fi
  VERIFAST_PATH="$(pwd)/verifast"
fi

echo 'Verifying, this will take a while, now is a great time to go make a cup of tea...'

echo '\n!!! Please note that the "inconsistency in axioms" message is a false positive, see https://github.com/verifast/verifast/issues/32 !!!\n'

$VERIFAST_PATH/bin/verifast -allow_dead_code -D VERIFAST -I include/ -shared src/structs/index_pool.c src/structs/map.c include/proof/*.c
