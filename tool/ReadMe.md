# Klint

You'll need Python 3, the root Makefile takes care of creating a venv for you.

Two layers:
- `kalm` adapts angr to perform exhaustive symbolic execution, and adds some features we need
- `klint` is the actual tool

Compile the NF yourself: for `libnf` verif of the NFs under `../nf`, use `make -f ../Makefile.nf` in the NF's folder;
for `bpf-jited` verif of the NFs under `../nf/bpf`, run `./compile-bpf.sh` in the NF's folder.

The intended entry point is `./klint.py`, use `--help` for usage instructions. Main args you'll be interested in:
- `--export-graphs` (for any target) exports DOT graphs in the `graphs/` output folder corresponding to paths in the code.
  There's one graph per iteration of symbex until a fixed-point is found.
  To visualize, use e.g. `for g in graphs/*.dot ; do dot -Tpng -o $g.png $g ; done` to convert .dot files to PNGs.
- For BPF JITed code, `--havoc-all` to havoc all maps if the code assumes maps are touched by user space. Or `--havoc xxx` to specifically havoc map `xxx`.

Klint is based on angr, so if you want to extend it the angr tutorial is a must: https://docs.angr.io/core-concepts

Klint also has some basic unit tests, run `python -m unittests`

Note that the "instruction limit" mentioned in the paper is not yet supported but should be trivial to add using angr's built-in features.


## Writing a specification

Specs are Python files. The files are actually executed using the standard Python interpreter, so any Python works.
Use the `assert` statement for assertions (though you can raise exceptions manually if that's your thing).

Use `|`, `&` and `~` instead of `or`, `and`, and `not` respectively, this is a Python limitation unfortunately.
(The custom objects we use must override this behavior, and only the operators can be overriden, not the keywords.)

Beware, Klint is based on `angr` which gives slicing and concatenation the opposite semantics compared to usual Python, i.e., `x.concat(y)` results in `y` using the lower bits.
Try it out by yourself in a Python shell to get familiar with this.

The way Klint interprets specs is by executing them in the interpreter passing special global variables (which you should not need to worry about),
but first prepending `klint/verif/spec_prefix.py` (to define packets, maps, ...) and `klint/verif/spec_utils.py` (utilities that use the `prefix` stuff).

Specs must start by defining the state using `m = Map(key_type, value_type)` statements, where `value_type` can be `...` to match any type.
This returns the map as it is after processing the packet.
These maps correspond to the ones abstracted from the implementation (e.g., an array is a map from indexes to values, an LPM is a map from prefixes to values, ...).
These maps have `length`, `forall(pred)` (where `pred` is a `lambda k, v`), `__contains__` (a.k.a. the `in` operator) and `__getitem__` (a.k.a. indexing).
They also have `old` to retrieve the map as it was before the packet was processed.
(There is also `Cell` for single-element maps, see `klint/verif/spec_prefix.py`)

A note about `forall` : do not use `assert` within a forall predicate, as assertions will not hold on the key/value at that point as these are unconstrained symbols.
Also do not use `if/else`, instead use the `if_then_else` spec builtin.
The predicate should _return_ an expression that will be evaluated on all map items, and the `forall` result itself can be asserted.
For instance, instead of `map.forall(... assert k == 0 ...)`, use `assert map.forall(... return k == 0 ...)`.

Verification succeeds if Klint can find implementation maps matching the specification maps such that all paths verify.
For an example of how to combine maps, check out `ExpiringSet` in `klint/verif/spec_utils.py`.

The spec function must be named `spec` and have arguments `(packet, config, transmitted_packet)`,
where `packet` is the input packet, `config` is the NF config, and `transmitted_packet` is the transmitted packet or `None`.

Packets have property `device` iff they were received/transmitted on a single device (the property raises an exception otherwise), `devices` for all devices they were received/transmitted on,
`data` for the entire data (byte array), `length` for the length and `time` for the reception time.
They also have helper properties such as `ether` for the Ethernet header; check out `_SpecPacket` in `klint/verif/spec_prefix.py` for the full list.

Finally, there is the `exists` built-in spec function which takes a `lambda value:` and returns whether the lambda is satisfiable,
which is useful for assertions such as "if the packet was transmitted, then there should be a key K in the map such that...".

In general, specs should state _what_, not _how_. There is no way to say "key/value pair P was added to map M", instead you should say "the map M contains key/value pair P".
You can also state things like "if key K was in the old version of the map, then the packet must have been forwarded, i.e., `transmitted_packet is not None`".

Tip: Values from the packet data are in the format `pkt_data_v_XXX_8` where `XXX` is an unique ID (irrelevant to their index in the packet data), each is 8 bits.
So if you have a 32-bit value you extract from the packet you will see 4 of those concatenated. Beware of the order in which you declare your things in the specs/contracts compared to the code!


## Writing contracts

Contracts are a bit messier than the paper suggests, though making them "nice" is just engineering work.

They are in `klint/externals/`, typically you'll want `structs/`. You will also need to specify in `klint/executor.py` which functions are available during init and during packet handling.

Look at the existing contracts to get an idea of what to do, and at `klint/ghostmaps.py` for the API of `state.maps`.

Some tips:
- When declaring the function to angr in the procedure init function, it's simpler to pretend the `struct xyz*` pointers are `void*` rather than detailing the struct to angr
- Access the state using `self.state`, unless you are in a `utils.fork_*` callback in which case the state is a parameter (do not use `self.state` in these!)
- Start with preconditions, including using `state.metadata.get` to get the metadata associated with a data structure pointer, as well as any "X must be concrete" preconditions (e.g., sizes in constructor functions)
- Whenever using `state.memory.load`/`state.memory.store`, specify the endness (unless it's just a load to validate that the pointer points to some useful state)
- Do not forget that loads are done with byte granularity, so don't get your bits and bytes confused
- Do not forget that "booleans" in C signatures are bitvectors of size `state.sizes.bool`, not actual booleans at the SMT level (i.e., not something like `claripy.BoolS(...)`)
