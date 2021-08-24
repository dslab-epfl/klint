#!/usr/bin/env python

import argparse

from klint import statistics
import klint.bpf.analysis as bpf_analysis
import klint.executor as nf_executor
import klint.verif.persistence as verif_persist
import klint.verif.executor as verif_executor

# kept here to ease debugging
#import tests.test
#tests.test.Tests().test_merge_leftget()
#sys.exit(0)


def verif(data_path, spec):
    # print them now just in case verif fails somehow
    for line in statistics.to_tsv():
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


def handle_libnf(args):
    cached_data_path = args.file + ".symbex-cache"
    if not args.use_cached_symbex:
        states, devices_count = nf_executor.execute_libnf(args.file)
        verif_persist.dump_data(states, devices_count, cached_data_path)
    verif(cached_data_path, args.spec)

def handle_fullstack(args):
    cached_data_path = args.file + ".symbex-cache"
    if not args.use_cached_symbex:
        states, devices_count = nf_executor.execute_nf(args.file)
        verif_persist.dump_data(states, devices_count, cached_data_path)
    verif(cached_data_path, args.spec)

def handle_bpf(args):
    ext_addrs = bpf_analysis.get_externals_addresses(args.binary)
    ext_maps = bpf_analysis.get_maps(args.maps)
    ext_names = bpf_analysis.get_externals_names(args.instructions)
    print(ext_addrs, ext_maps, ext_names)

parser = argparse.ArgumentParser()
parser.add_argument('--use-cached-symbex', type=bool, default=False, help='Verify only, using cached symbolic execution results')

subparsers = parser.add_subparsers()

parser_libnf = subparsers.add_parser('libnf', help='Verify a libNF alone')
parser_libnf.add_argument('file', type=str, help='Path to the libNF .so')
parser_libnf.add_argument('spec', type=str, nargs='?', help='Path to the specification')
parser_libnf.set_defaults(func=handle_libnf)

parser_fullstack = subparsers.add_parser('fullstack', help='Verify full-stack')
parser_fullstack.add_argument('file', type=str, help='Path to the full-stack binary')
parser_fullstack.add_argument('spec', type=str, nargs='?', help='Path to the specification')
parser_fullstack.set_defaults(func=handle_fullstack)

parser_bpf = subparsers.add_parser('bpf-jited', help='Verify a JITed BPF program')
parser_bpf.add_argument('binary', type=str, help='Path to the dumped JITed binary function')
parser_bpf.add_argument('maps', type=str, help='Path to the contents of the .maps section')
parser_bpf.add_argument('instructions', type=str, help='Path to the dumped BPF instructions')
parser_bpf.add_argument('spec', type=str, nargs='?', help='Path to the specification')
parser_bpf.set_defaults(func=handle_bpf)

args = parser.parse_args()
args.func(args)
