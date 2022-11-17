#!/usr/bin/env python

import argparse
from collections.abc import Callable
import importlib.util
import os
import shutil

from klint import statistics
import klint.executor as nf_executor
import klint.verif.persistence as verif_persist
import klint.verif.executor as verif_executor

# kept here to ease debugging
#import tests.test ; import sys
#tests.test.Tests().test_forall_subset() ; sys.exit(0)

def handle_graph(graph: str) -> None:
    global graph_counter
    if graph_counter is None:
        return
    with open('graphs/' + str(graph_counter) + '.dot', 'w') as file:
        file.write(graph)
    graph_counter = graph_counter + 1

def load_spec(spec_path: str) -> Callable[..., None]:
    spec = importlib.util.spec_from_file_location("spec", spec_path)
    assert spec is not None, "unable to load spec"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.spec


def verif(data_path, spec_path):
    if spec_path is None:
        print("No specification. Not verifying.")
    else:
        verif_executor.verify(
            verif_persist.load_data(data_path),
            load_spec(spec_path),
        )

    for line in statistics.to_tsv():
        print(line)

def handle_libnf(args):
    cached_data_path = args.file + ".symbex-cache"
    if not args.use_cached_symbex or not os.path.isfile(cached_data_path):
        states, devices_count = nf_executor.execute_libnf(args.file, graph_handler=handle_graph)
        verif_persist.dump_data(states, devices_count, cached_data_path)
    verif(cached_data_path, args.spec)

def handle_fullstack(args):
    cached_data_path = args.file + ".symbex-cache"
    if not args.use_cached_symbex or not os.path.isfile(cached_data_path):
        states, devices_count = nf_executor.execute_nf(args.file)
        verif_persist.dump_data(states, devices_count, cached_data_path)
    verif(cached_data_path, args.spec)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--use-cached-symbex', action='store_true', help='Verify only, using cached symbolic execution results')
    parser.add_argument('--export-graphs', action='store_true', help='Dump the state graphs resulting from each iteration of symbolic execution')

    subparsers = parser.add_subparsers(dest='command', required=True)

    parser_libnf = subparsers.add_parser('libnf', help='Verify a libNF alone')
    parser_libnf.add_argument('file', type=str, help='Path to the libNF .so')
    parser_libnf.add_argument('spec', type=str, nargs='?', help='Path to the specification')
    parser_libnf.set_defaults(func=handle_libnf)

    parser_fullstack = subparsers.add_parser('fullstack', help='Verify full-stack')
    parser_fullstack.add_argument('file', type=str, help='Path to the full-stack binary')
    parser_fullstack.add_argument('spec', type=str, nargs='?', help='Path to the specification')
    parser_fullstack.set_defaults(func=handle_fullstack)

    args = parser.parse_args()

    global graph_counter
    if args.export_graphs:
        graph_counter = 0
        if os.path.isdir('graphs'):
            shutil.rmtree('graphs')
        os.makedirs('graphs')
    else:
        graph_counter = None

    #For debugging:
    #args = parser.parse_args(['--use-cached-symbex', 'libnf', 'D:/Projects/vigor-binary-experiments/nf/firewall/libnf.so', 'D:/Projects/vigor-binary-experiments/nf/firewall/spec.py'])
    args.func(args)

if __name__ == "__main__":
    import sys

    sys.exit(main())
