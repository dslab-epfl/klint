#!/usr/bin/env python

import os
from pathlib import Path # TODO in general we should use Path everywhere, or os everywhere, not this weird mix
import sys

from klint import statistics
import klint.executor as nf_executor
import klint.verif.persistence as verif_persist
import klint.verif.executor as verif_executor


full_stack = False
nf_to_verify = "firewall"
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

# print them now just in case verif fails somehow
stats = statistics.to_tsv()
for line in stats:
    print(line)
"""
spec_path = Path(nf_root_folder) / "spec.py" # TODO spec needs to be an arg
if spec_path.exists():
    spec = spec_path.read_text()
    verif_executor.verify(verif_persist.load_data(cached_data_path), spec)
    stats = statistics.to_tsv()
    for line in stats:
        print(line)
else:
    print("No specification. Not verifying.")

(Path(__file__).parent / "symbex.stats").write_text("\n".join(stats))
"""