#!/usr/bin/env python

# Standard/External libraries
import os
from pathlib import Path
import sys

# Us
import nf.executor as nf_executor
import verif.persistence as verif_persist
import verif.executor as verif_executor


#nf_executor.execute_full(os.path.join(Path(__file__).parent.absolute(), "..", "os", "bin"))
#sys.exit(0)

nf_to_verify = "vigor-firewall"
if len(sys.argv) >= 2:
    nf_to_verify = sys.argv[1]

use_cached_results = True
if len(sys.argv) >= 3 and sys.argv[2] == "use-cache":
    use_cached_results = True

nf_root_folder = os.path.join(Path(__file__).parent.absolute(), "..", "nf", nf_to_verify)
cached_data_path =  os.path.join(nf_root_folder, "symbex.result")

if not use_cached_results:
    state_pairs, devices_count = nf_executor.execute(os.path.join(nf_root_folder, "libnf.so"))
    verif_persist.dump_data(state_pairs, devices_count, cached_data_path)

spec = (Path(nf_root_folder) / "spec.py").read_text()
for data in verif_persist.load_data(cached_data_path):
    verif_executor.verify(data, spec)
