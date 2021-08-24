from collections import namedtuple

BpfMapDef = namedtuple('BpfMapDef', ['type', 'key_size', 'value_size', 'max_entries', 'flags'])
