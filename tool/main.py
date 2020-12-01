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

spec = (Path(__file__).parent / ".." / "nf" / nf_to_verify / "spec.py").read_text()

states, devices_count = nf_executor.execute(os.path.join(Path(__file__).parent.absolute(), "..", "nf", nf_to_verify, "libnf.so"))

for state in states:
    verif_executor.verify(state, devices_count, spec)