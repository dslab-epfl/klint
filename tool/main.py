#!/usr/bin/env python

# Standard/External libraries
import os
from pathlib import Path
import sys

# Us
import nf.executor as nf_executor
import verif.executor as verif_executor

nf_to_verify = "router"

if len(sys.argv) >= 2:
    nf_to_verify = sys.argv[1]

# Special case for Rust binaries
bin_name = "libnf.so"
if nf_to_verify == "rs-vigor-policer":
    nf_to_verify = os.path.join(nf_to_verify, "target", "debug")  
    bin_name = "librs_vigor_policer.so"

spec = (Path(__file__).parent / ".." / "nf" / nf_to_verify / "spec.py").read_text()

states, devices_count = nf_executor.execute(os.path.join(Path(__file__).parent.absolute(), "..", "nf", nf_to_verify, bin_name))

for state in states:
    verif_executor.verify(state, devices_count, spec)