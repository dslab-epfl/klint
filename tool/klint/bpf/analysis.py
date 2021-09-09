import claripy

from klint.bpf.externals import BpfMapDef

def get_calls(path):
    with open(path, 'r') as file:
        return [(int(l[0], 16), l[1]) for l in [l.strip().split(' ') for l in file.readlines()]]

def get_maps(path, ptr_size):
    def to_bvs(text):
        chunks = [text[i:i + 8] for i in range(0, len(text), 8)]
        if len(chunks[-1]) != 8:
            raise Exception('Unexpected number of bytes in map...')
        return [claripy.BVV(int(c, 16), 32).reversed.zero_extend(ptr_size - 32) for c in chunks]

    with open(path, 'r') as file:
        return [(a, n, BpfMapDef(d[0], d[1], d[2], d[3], d[4])) for (a, n, d) in [(claripy.BVV(int(l[0], 16), ptr_size), l[1], to_bvs(l[2])) for l in [l.strip().split(' ') for l in file.readlines()]]]
