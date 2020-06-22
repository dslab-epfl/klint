import angr
import claripy
from angr.state_plugins.plugin import SimStatePlugin
import executors.binary.utils as utils
import copy

class Metadata(SimStatePlugin):
    merging_funcs = {}
    state_to_merge = None

    # func is (items, states) -> new_value; can return None to delete the item, if it cannot be sensibly merged
    # pre_process is ([items_by_obj for state in states], states) -> result
    # post_process is (merged_state, pre_process_result) -> None
    @staticmethod
    def set_merging_func(cls, func, pre_process=None, post_process=None):
        if pre_process is None and post_process is not None:
            raise angr.AngrExitError("Cannot have post-processing without pre-processing")
        if cls in Metadata.merging_funcs and Metadata.merging_funcs[cls] != (pre_process, func, post_process):
            raise angr.AngrExitError("Cannot change merging functions once set")
        Metadata.merging_funcs[cls] = (pre_process, func, post_process)


    def __init__(self, items=None):
        SimStatePlugin.__init__(self)
        self.items = {} if items is None else items
        self.to_do = [] # stupid hack: we want to do something after a merge, but after everything has been merged..


    def set_state(self, state):
        SimStatePlugin.set_state(self, state)


    @SimStatePlugin.memo
    def copy(self, memo):
        return Metadata(copy.deepcopy(self.items))


    def merge(self, others, merge_conditions, common_ancestor=None):
        def _eq(a, b):
            if a is None:
                return b is None
            if b is None:
                return False
            if isinstance(a, claripy.ast.base.Base) and isinstance(b, claripy.ast.base.Base):
                return a.structurally_match(b)
            if isinstance(a, claripy.ast.base.Base) or isinstance(b, claripy.ast.base.Base):
                raise angr.AngrExitError("_eq gave up: " + str(a) + " and " + str(b))
            if hasattr(a, '_asdict') and hasattr(b, '_asdict'):
                ad = a._asdict()
                bd = b._asdict()
                return all(_eq(ad[k], bd[k]) for k in set(ad.keys()).union(bd.keys()))
            if isinstance(a, list) and isinstance(b, list):
                return len(a) == len(b) and all(_eq(a[n], b[n]) for n in range(len(a)))
            if isinstance(a, tuple) and isinstance(b, tuple):
                return _eq(list(a), list(b))
            return a == b

        # HACK: ignore clock.Time, we don't want to merge it anyway
        time_key = next((k for items in [o.items.keys() for o in [self] + others] for k in items if "clock.Time" in str(k)), None)
        if any(len([k for k in o.items.keys() if k != time_key]) != len([k for k in self.items.keys() if k != time_key]) for o in others):
            raise angr.AngrExitError("Merging Metadata instances with different keys is not supported yet")
        if time_key is not None:
            self.remove_all(time_key)

        my_state = Metadata.state_to_merge # see HACK below - at this point 'self.state' might've been modified by other plugins already
        Metadata.state_to_merge = None

        for cls in self.items:
            if any(cls not in o.items for o in others) or any(len(o.items[cls]) != len(self.items[cls]) for o in others):
                raise angr.AngrExitError("Merging Metadata instances with different keys is not supported yet")

            (pre_process, merge, post_process) = Metadata.merging_funcs.get(cls, (None, None, None))

            if pre_process is not None:
                pre_process_result = pre_process([self.items[cls]] + [o.items[cls] for o in others], [my_state] + [o.state for o in others])

            for (k, v) in self.items[cls]:
                values = [v]
                states = [my_state]
                for o in others + [common_ancestor]:
                    if cls not in o.items:
                        continue
                    ov = [v2 for (k2, v2) in o.items[cls] if k is k2]
                    if len(ov) == 0:
                        continue
                    if len(ov) > 1:
                        raise angr.AngrExitError("Merging Metadata instances with different keys is not supported yet")
                    ov = ov[0]
                    if all(not _eq(ov, vvv) for vvv in values): # poor man's set
                        values.append(ov)
                        states.append(o.state)
                if len(values) != 1: # if 1, nothing to do, all values were exactly the same
                    if merge is None:
                        raise angr.AngrExitError("Metadata does not know how to merge " + str(cls) + ", please use Metadata.set_merging_func")
                    new_v = merge(values, states)
                    if new_v is None:
                        self.remove(cls, k)
                    else:
                        self.set(k, new_v, override=True)

            if post_process is not None:
                cls_copy = cls # avoid 'cls' taking on the last value due to python capturing rules...
                self.to_do.append((lambda s, a: a(s.state, pre_process_result), post_process))

        return True


    # HACK: For merging to work correctly, we need to know about the state being merged into before any other plugins can change it
    def call_me_before_merge_always(self):
        Metadata.state_to_merge = self.state.copy()

    # HACK: For merging to work correctly with post-processing functions, this MUST be called immediately on the result of state.merge
    def call_me_after_merge_always(self):
        for (func, arg) in self.to_do:
            func(self, arg)
        self.to_do = []


    def items_copy(self): # for verification purposes
        return self.items.copy()


    def _get(self, cls, key):
        if cls not in self.items:
            return []
        return [(k, v) for (k, v) in self.items[cls] if utils.definitely_true(self.state.solver, k == key) and isinstance(v, cls)]


    def get(self, cls, key, default=None):
        results = self._get(cls, key)
        if len(results) == 0:
            if default is None:
                raise angr.AngrExitError("No metadata for key: " + str(key) + " of class: " + str(cls))
            else:
                self.set(key, default)
                return default

        if len(results) > 1:
            raise angr.AngrExitError("More than one matching metadata of type " + str(cls) + " for key: " + str(key))

        return results[0][1]


    def get_all(self, cls):
        return self.items.get(cls, [])


    def set(self, key, value, override=False):
        cls = type(value)
        results = self._get(cls, key)
        if len(results) > 1:
            raise angr.AngrExitError("More than one existing metadata of type " + str(cls) + " for key: " + str(key))

        has_already = len(results) == 1
        if has_already:
            if override:
                self.items[cls] = [(k, v) for (k, v) in self.items[cls] if k is not results[0][0]] # using remove() tests by value, which ends up converting claripy ASTs to bool, which they don't like
            else:
                raise angr.AngrExitError("There is already metadata of type " + str(cls) + " for key: " + str(key) + ", namely " + str(results))

        if override and not has_already:
            raise angr.AngrExitError("There is no metadata of type " + str(cls) + " to override for key: " + str(key))

        if cls not in self.items:
            self.items[cls] = []

        self.items[cls].append((key, value))


    def remove(self, cls, key):
        self.items[cls] = [(k, v) for (k, v) in self.items[cls] if k is not key] # same comment as in set


    def remove_all(self, cls):
        if cls in self.items:
            del self.items[cls]
