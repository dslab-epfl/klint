#!/bin/sh

# this worked as of VeriFast commit 5d6271c82a82aff7536db91576e5f673ebf06182
# (but building it from source requires a bunch of stuff, including ocaml/opam, so let's download it instead)

if [ "$VERIFAST_PATH" = '' ]; then
  echo 'Using local VeriFast. If you want to use a custom one, set $VERIFAST_PATH to the root folder of a VeriFast distribution (which contains bin/verifast).\n'

  if [ ! -d 'verifast' ]; then
    echo 'Local VeriFast not found, downloading...'
    # we have to handle the redirect via a meta refresh manually...
    # TODO replace by a named release when there's a new one with the latest changes (after 21.04)
    wget -q 'https://storage.googleapis.com/verifast-nightlies/verifast-nightly-linux-latest.html'
    VF_GZ="$(grep -F '<meta' verifast-nightly-linux-latest.html | sed 's|.*URL=latest/linux/\(.*\)".*|\1|')"
    rm 'verifast-nightly-linux-latest.html'
    wget -q "https://storage.googleapis.com/verifast-nightlies/latest/linux/$VF_GZ"
    tar -xf "$VF_GZ"
    rm "$VF_GZ"
    mv "$(echo "$VF_GZ" | sed 's/.tar.gz//')" 'verifast'
  fi
  VERIFAST_PATH="$(pwd)/verifast"
fi

echo 'Verifying, this will take ~20min, now is a great time to go make a cup of tea...'

# TODO it'd be nice to have a proof that did not emit them anyway...
echo '\nPlease note that "inconsistency in axioms" messages are false positives, see https://github.com/verifast/verifast/issues/32\n'

VF_COMMAND="$VERIFAST_PATH/bin/verifast -allow_dead_code -D VERIFAST -I include/ -shared -emit_vfmanifest"

# redux cannot prove bitopsutils and mod-pow2 but z3 can, and vice-versa for the others, so we use the right prover for the right file...
$VF_COMMAND -prover redux include/proof/arith.c \
                          include/proof/listutils-lemmas.c \
                          include/proof/modulo.c
$VF_COMMAND -prover z3v4.5 include/proof/arith.vfmanifest \
                           include/proof/listutils-lemmas.vfmanifest \
                           include/proof/modulo.vfmanifest \
                           include/proof/bitopsutils.c \
                           include/proof/mod-pow2.c
$VF_COMMAND -prover redux include/proof/arith.vfmanifest \
                          include/proof/listutils-lemmas.vfmanifest \
                          include/proof/modulo.vfmanifest \
                          include/proof/bitopsutils.vfmanifest \
                          include/proof/mod-pow2.vfmanifest \
                          src/os/memory_alloc.c \
                          src/os/config.c \
                          src/structs/index_pool.c \
                          src/structs/map.c
