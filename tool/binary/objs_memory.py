import angr
import claripy
from collections import namedtuple

from binary import utils


class ObjectsMemoryMixin(angr.storage.memory_mixins.MemoryMixin):
    Metadata = namedtuple('ObjectsMemoryMetadata', ['count', 'size', 'reader', 'writer', 'endness'])

    def load(self, addr, size=None, endness=None, **kwargs):
        (obj, index, offset) = utils.base_index_offset(self.state, addr, ObjectsMemoryMixin.Metadata, allow_failure=True)
        meta = self.state.metadata.get_or_none(ObjectsMemoryMixin.Metadata, obj) if obj is not None else None
        if meta is None:
            return super().load(addr, size=size, endness=endness, **kwargs)

        result = meta.reader(self.state, obj, index, offset, size)
        if endness is not None and endness != meta.endness:
            result = result.reversed
        return result

    def store(self, addr, data, size=None, endness=None, **kwargs):
        (obj, index, offset) = utils.base_index_offset(self.state, addr, ObjectsMemoryMixin.Metadata, allow_failure=True)
        meta = self.state.metadata.get_or_none(ObjectsMemoryMixin.Metadata, obj) if obj is not None else None
        if meta is None:
            super().store(addr, data, size=size, endness=endness, **kwargs)
            return

        if endness is not None and endness != meta.endness:
            data = data.reversed
        meta.writer(self.state, obj, index, offset, data)


    # reader: (state, base, index, offset, size) -> value
    # writer: (state, base, index, offset, value) -> void
    def create_special_object(self, name, count, size, reader, writer):
        obj = claripy.BVS(name, self.state.sizes.ptr)
        self.state.metadata.append(obj, ObjectsMemoryMixin.Metadata(count, size, reader, writer, self.state.arch.memory_endness))
        return obj
