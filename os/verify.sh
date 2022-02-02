#!/bin/sh

# This worked as of VeriFast commit d08bdd3ec84dc3e6a1cc609527932e665759c884
# But not on 21.04, the latest stable version, due to some missing stuff we added later
# Building VeriFast from source requires a bunch of stuff, including ocaml & opam, so let's download it instead
# unless the user sets VERIFAST_PATH in which case we use that

# TODO: once there's a stable release newer than 21.04, use that instead of trickery to download a nightly

if [ "$VERIFAST_PATH" = '' ]; then
  echo 'Using local VeriFast. If you want to use a custom one, set $VERIFAST_PATH to the root folder of a VeriFast distribution (which contains bin/verifast).\n'
  VERIFAST_PATH="$(pwd)/verifast"

  if [ ! -d 'verifast' ]; then
    echo 'Local VeriFast not found, downloading...'
    VF_URL="$(wget 'https://github.com/verifast/verifast/releases/tag/nightly' -q -O - | grep -o '/verifast.*linux.tar.gz')"
    wget "https://github.com$VF_URL" -q -O 'verifast.tar.gz'
    mkdir "$VERIFAST_PATH"
    tar --strip-components 1 -C "$VERIFAST_PATH" -xf 'verifast.tar.gz'
    rm "verifast.tar.gz"
  fi
fi

echo '\nVerifying, this will take 10min, now is a great time to go make a cup of tea...'
echo '  (please note that "inconsistency in axioms" messages are false positives, see https://github.com/verifast/verifast/issues/32)\n'

VF_COMMAND="$VERIFAST_PATH/bin/verifast -allow_dead_code -D VERIFAST -I include/ -shared -emit_vfmanifest"

# redux cannot prove bitopsutils and mod-pow2 but z3 can, and vice-versa for the others, so we use the "right" prover for the "right" file...
# ideally we'd rewrite the proofs to all work on one prover but that means lots of effort for little benefit
$VF_COMMAND -prover redux include/proof/arith.c \
                          include/proof/listutils-lemmas.c \
                          include/proof/modulo.c
$VF_COMMAND -prover z3v4.5 include/proof/arith.vfmanifest \
                           include/proof/listutils-lemmas.vfmanifest \
                           include/proof/modulo.vfmanifest \
                           include/proof/bitopsutils.c \
                           include/proof/mod-pow2.c
$VF_COMMAND -prover redux -allow_assume \
                          include/proof/arith.vfmanifest \
                          include/proof/listutils-lemmas.vfmanifest \
                          include/proof/modulo.vfmanifest \
                          include/proof/bitopsutils.vfmanifest \
                          include/proof/mod-pow2.vfmanifest \
                          src/os/memory_alloc.c \
                          src/os/config.c \
                          src/structs/index_pool.c \
                          src/structs/map.c

echo '\nNow we grep for any assumptions in proofs...\n'
grep -Fr --exclude=\*.vfmanifest -B 2 'assume' src/os/*.c src/structs/ include/
