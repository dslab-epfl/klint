import angr
import claripy
from collections import namedtuple

from kalm import utils


class ObjectsMemoryMixin(angr.storage.memory_mixins.MemoryMixin):
    Metadata = namedtuple('ObjectsMemoryMetadata', ['count', 'size', 'reader', 'writer', 'endness'])

    def load(self, addr, size=None, endness=None, **kwargs):
        (obj, index, offset) = utils.base_index_offset(self.state, addr, ObjectsMemoryMixin.Metadata, allow_failure=True)
        meta = self.state.metadata.get_or_none(ObjectsMemoryMixin.Metadata, obj) if obj is not None else None
        if meta is None:
            return super().load(self.state.solver.eval_one(addr), size=size, endness=endness, **kwargs)

        result = meta.reader(self.state, obj, index, offset, size)
        if endness is not None and endness != meta.endness:
            result = result.reversed
        return result

    def store(self, addr, data, size=None, endness=None, **kwargs):
        (obj, index, offset) = utils.base_index_offset(self.state, addr, ObjectsMemoryMixin.Metadata, allow_failure=True)
        meta = self.state.metadata.get_or_none(ObjectsMemoryMixin.Metadata, obj) if obj is not None else None
        if meta is None:
            super().store(self.state.solver.eval_one(addr), data, size=size, endness=endness, **kwargs)
            return

        if endness is not None and endness != meta.endness:
            data = data.reversed
        meta.writer(self.state, obj, index, offset, data)


    # reader: (state, base, index, offset, size) -> value
    # writer: (state, base, index, offset, value) -> void
    def set_special_object(self, obj, count, size, reader, writer):
        self.state.metadata.append(obj, ObjectsMemoryMixin.Metadata(count, size, reader, writer, self.state.arch.memory_endness))
