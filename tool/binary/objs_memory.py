import angr
import claripy
from collections import namedtuple


class ObjectsMemoryMixin(angr.storage.memory_mixins.MemoryMixin):
    Metadata = namedtuple('ObjectsMemoryMetadata', ['size', 'reader', 'writer'])

    def load(self, addr, size=None, endness=None, **kwargs):
        (obj, offset) = self._obj_offset(addr)

        meta = self.state.metadata.get_or_none(ObjectsMemoryMixin.Metadata, obj) if obj is not None else None
        if meta is None:
            return super().load(addr, size=size, endness=endness, **kwargs)

        assert size is None, "too lazy to implement this"
        result = meta.reader(self.state, obj, offset // meta.size)
        if endness is not None and endness != self.endness:
            result = result.reversed
        return result


    def store(self, addr, data, size=None, endness=None, **kwargs):
        (obj, offset) = self._obj_offset(addr)

        meta = self.state.metadata.get_or_none(ObjectsMemoryMixin.Metadata, obj) if obj is not None else None
        if meta is None:
            super().store(addr, data, size=size, endness=endness, **kwargs)
        else:
            assert size is None, "too lazy to implement this"
            if endness is not None and endness != self.endness:
                data = data.reversed
            meta.writer(self.state, obj, offset // meta.size, data)


    # reader: (state, base, offset) -> value
    # writer: (state, base, offset, value) -> void
    def create_special_object(self, name, size, reader, writer):
        obj = claripy.BVS(name, self.state.sizes.ptr)
        self.state.metadata.append(obj, ObjectsMemoryMixin.Metadata(size, reader, writer))


    def _obj_offset(self, addr):
        if isinstance(addr, claripy.ast.Base) and addr.op == '__add__':
            cands = [arg for arg in addr.args if arg.symbolic]
            if len(cands) == 1:
                return (cands[0], sum([a for a in addr.args if not a.structurally_match(cands[0])]))
        return (None, None)