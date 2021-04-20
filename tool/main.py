#!/usr/bin/env python

import os
from pathlib import Path # TODO in general we should use Path everywhere, or os everywhere, not this weird mix
import sys

from binary import statistics
import nf.executor as nf_executor
import verif.persistence as verif_persist
import verif.executor as verif_executor


#from tests.test import Tests
#Tests().test_forall_cross_o2first_weird()
#sys.exit(0)

full_stack = True
nf_to_verify = "nop"
use_cached_results = False


if len(sys.argv) >= 2:
    nf_to_verify = sys.argv[1]
if len(sys.argv) >= 3 and sys.argv[2] == "use-cache": # TODO reverse this switch, make it "force reverify" or smth
    use_cached_results = True

nf_root_folder = os.path.join(Path(__file__).parent.absolute(), "..", "nf", nf_to_verify)
bin_root_folder = os.path.join(Path(__file__).parent.absolute(), "..", "os")

if full_stack:
    cached_data_path = os.path.join(bin_root_folder, "symbex.result")
    if not use_cached_results:
        states, devices_count = nf_executor.execute_nf(os.path.join(bin_root_folder, "bin"))
        verif_persist.dump_data(states, devices_count, cached_data_path)
else:
    cached_data_path =  os.path.join(nf_root_folder, "symbex.result")
    if not use_cached_results:
        states, devices_count = nf_executor.execute_libnf(os.path.join(nf_root_folder, "libnf.so"))
        verif_persist.dump_data(states, devices_count, cached_data_path)

spec = (Path(nf_root_folder) / "spec.py").read_text() # TODO spec needs to be an arg
verif_executor.verify(verif_persist.load_data(cached_data_path), spec)

(Path(__file__).parent / "symbex.stats").write_text("\n".join(statistics.to_tsv())) # TODO print them out as well? nicely
