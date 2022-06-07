#!/usr/bin/env python

import argparse
import os
import shutil

from klint import statistics
import klint.bpf.analysis as bpf_analysis
import klint.bpf.detection as bpf_detection
import klint.bpf.executor as bpf_executor
import klint.executor as nf_executor
import klint.verif.persistence as verif_persist
import klint.verif.executor as verif_executor

# kept here to ease debugging
#import tests.test ; import sys
#tests.test.Tests().test_forall_subset() ; sys.exit(0)

def handle_graph(graph):
    global graph_counter
    if graph_counter is None:
        return
    with open('graphs/' + str(graph_counter) + '.dot', 'w') as file:
        file.write(graph)
    graph_counter = graph_counter + 1

def verif(data_path, spec_path):
    if spec_path is None:
        print("No specification. Not verifying.")
    else:
        with open(spec_path, 'r') as spec_file:
            spec = spec_file.read()
        verif_executor.verify(verif_persist.load_data(data_path), spec)

    for line in statistics.to_tsv():
        print(line)


def handle_libnf(args):
    cached_data_path = args.file + ".symbex-cache"
    if not args.use_cached_symbex:
        states, devices_count = nf_executor.execute_libnf(args.file, graph_handler=handle_graph)
        verif_persist.dump_data(states, devices_count, cached_data_path)
    verif(cached_data_path, args.spec)

def handle_fullstack(args):
    cached_data_path = args.file + ".symbex-cache"
    if not args.use_cached_symbex:
        states, devices_count = nf_executor.execute_nf(args.file)
        verif_persist.dump_data(states, devices_count, cached_data_path)
    verif(cached_data_path, args.spec)

def handle_bpf(args):
    cached_data_path = args.binary + ".symbex-cache"
    if args.override_linux_version is not None:
        bpf_detection.override_linux_version(args.override_linux_version)
    if args.override_64bit is not None:
        bpf_detection.override_64bit(args.override_64bit)
    states, devices_count = bpf_executor.execute(args.binary, args.calls, args.maps, args.havoc, args.havoc_all)
    verif_persist.dump_data(states, devices_count, cached_data_path)
    verif(cached_data_path, args.spec)

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

parser_bpf = subparsers.add_parser('bpf-jited', help='Verify a JITed BPF program')
parser_bpf.add_argument('binary', type=str, help='Path to the dumped JITed binary function')
parser_bpf.add_argument('calls', type=str, help='Path to a file with one line per called BPF helper, format "[hex kernel address] [name]"')
parser_bpf.add_argument('maps', type=str, help='Path to a file with one line per BPF map, format "[hex kernel address] [name] [hex data]"')
parser_bpf.add_argument('spec', type=str, nargs='?', help='Path to the specification')
parser_bpf.add_argument('--override-linux-version', type=str, help='Override Linux version detection')
parser_bpf.add_argument('--override-64bit', type=bool, help='Override 64bit detection')
parser_bpf.add_argument('--havoc', type=str, action='append', default=[], help='Map name to be havoced')
parser_bpf.add_argument('--havoc-all', action='store_true', help='Havoc all maps')
parser_bpf.set_defaults(func=handle_bpf)

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
