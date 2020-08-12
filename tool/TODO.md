If perf is an issue, write a custom "dictionary with claripy ASTs as keys that compares them by structural equality" class (but maybe the solver is slow enough that this doesn't matter?)
The map is a Frankenstein copy/paste, fix it, and ensure capacity is a multiple of 2 like it needs
allow 0-capacity maps and dchains...

update pysmt to 0.9.0 to remove the deprecation warning about abc


check if expire ever goes into "nope"


grep -Fr assume os/
