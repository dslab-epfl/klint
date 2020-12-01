# Standard/External libraries
import angr
import claripy
from angr.state_plugins.plugin import SimStatePlugin
import copy

# Us
from . import utils
from .hash_dict import HashDict
from .exceptions import SymbexException

# Optimization: objects are compared structurally instead of with the solver, which might cause spurious failures
# (this does not work unless ghost maps are doing the "use existing items if possible in get" optimization)

class Metadata(SimStatePlugin):
    merge_funcs = {}

    # func_across takes as input ([states], [objs], ancestor_state)
    #                and returns [(ID, [objs], lambda (state, [meta]): None or [meta] to overwrite)]
    #                fixed-point if the returned [(ID, [objs])] is a superset of the previous one
    # func_one takes as input ([states], obj, ancestor_state)
    #             and returns (meta, has_changed)
    #             fixed-point if not has_changed
    # Regardless of whether this method is called for a given class,
    # metadata that is not present in the ancestor state, regardless of value, will be discarded.
    # If this method is not called for a given class,
    # metadata of that class is kept if it is structurally equal in all states and discarded otherwise
    @staticmethod
    def set_merge_funcs(cls, func_across, func_one):
        if cls in Metadata.merge_funcs and Metadata.merge_funcs[cls] != (func_across, func_one):
            raise SymbexException("Cannot change merge functions once set")
        Metadata.merge_funcs[cls] = (func_across, func_one)


    def __init__(self, items=None, merge_across_results=None):
        SimStatePlugin.__init__(self)
        self.items = items or {}
        self.merge_across_results = merge_across_results or {}


    @SimStatePlugin.memo
    def copy(self, memo):
        return Metadata(items=copy.deepcopy(self.items), merge_across_results=copy.deepcopy(self.merge_across_results))


    # HACK: For merging to work correctly, immediately before calling:
    #   (merged_state, _, _) = state.merge(*other_states, common_ancestor=ancestor_state)
    # one must call:
    #   opaque_value = state.metadata.notify_impending_merge(other_states, ancestor_state)
    # and immediately after one must call:
    #   reached_fixpoint = merged_state.metadata.notify_completed_merge(opaque_value)
    def notify_impending_merge(self, other_states, ancestor_state):
        # note that we keep track of objs as their string representations to avoid comparing Claripy ASTs (which don't like ==)
        across_previous_results = copy.deepcopy(ancestor_state.metadata.merge_across_results)
        any_individual_changed = False

        merged_items = {}
        across_results = {}
        for (cls, items) in self.items.items():
            if cls not in ancestor_state.metadata.items:
                # Ignore any metadata class that was not already in the ancestor state
                continue
            # Ignore any metadata key that was not already in the ancestor state
            common_keys = ancestor_state.metadata.items[cls].keys()

            merged_items[cls] = HashDict()
            if cls in Metadata.merge_funcs:
                across_results[cls] = Metadata.merge_funcs[cls][0]([self.state] + other_states, common_keys, ancestor_state)
                # To check if we have reached a superset of the previous across_results, remove all values we now have
                for (id, objs, _) in across_results[cls]:
                    if cls in across_previous_results:
                        try:
                            across_previous_results[cls].remove((id, list(map(str, objs))))
                        except ValueError:
                            pass # was not in across_previous_results[cls], that's OK
                # Merge individual values, keeping track of whether any of them changed
                for key in common_keys:
                    (merged_value, has_changed) = Metadata.merge_funcs[cls][1]([self.state] + other_states, key, ancestor_state)
                    any_individual_changed = any_individual_changed or has_changed
                    merged_items[cls][key] = merged_value
            else:
                # No merge function, keep all of the ones that are structurally equal, discard the others
                for key in common_keys:
                    value = self.get(cls, key)
                    if all(utils.structural_eq(other.metadata.get(cls, key), value) for other in other_states):
                        merged_items[cls][key] = value

        # As the doc states, fixpoint if all merges resulted in the old result and the across_results are a superset
        reached_fixpoint = not any_individual_changed and all(len(items) == 0 for items in across_previous_results.values())
        return (merged_items, across_results, reached_fixpoint)

    def notify_completed_merge(self, opaque_value):
        (merged_items, across_results, reached_fixpoint) = opaque_value
        self.merge_across_results = {cls: [(id, list(map(str, objs))) for (id, objs, _) in items] for (cls, items) in across_results.items()}
        self.items = merged_items

        for (cls, items) in across_results.items():
            for (_, objs, func) in items:
                vals = [self.get(cls, obj) for obj in objs]
                new_vals = func(self.state, vals)
                if new_vals is not None:
                    for (obj, new_val) in zip(objs, new_vals):
                        self.set(obj, new_val, override=True)

        return reached_fixpoint


    def merge(self, others, merge_conditions, common_ancestor=None):
        # No logic here because at this point other plugins may have already been merged,
        # including the solver, which means self.state.solver.constraints may have the merged constraints
        # instead of the pre-merge constraints we need.
        return True


    def items_copy(self): # for verification purposes
        return self.items.copy()

    def _get_value(self, cls, key):
        map = self.items.get(cls, None)
        if map is None:
            return None
        return map[key]


    def get(self, cls, key, default=None):
        value = self._get_value(cls, key)
        if value is None:
            if default is None:
                raise SymbexException(f"No metadata for key: {key} of class: {cls}")
            else:
                self.set(key, default)
                return default

        return value


    def get_all(self, cls):
        return self.items.get(cls, HashDict())

    def get_unique(self, cls):
        all = self.get_all(cls)
        if len(all) == 0:
            return None
        if len(all) == 1:
            return all.values()[0]
        raise SymbexException(f"No unique metadata for type {cls}")


    def set(self, key, value, override=False):
        cls = type(value)
        existing = self._get_value(cls, key)
        if existing is None:
            if override:
                raise SymbexException(f"There is no metadata of type {cls} to override for key {key}")
            map = self.items.get(cls, None)
            if map is None:
                map = HashDict()
                self.items[cls] = map
            map[key] = value
        else:
            if not override:
                raise SymbexException(f"There is already metadata of type {cls} for key {key}, namely {existing}")
            self.items[cls][key] = value


    def remove(self, cls, key):
        del self.items[cls][key]

    def remove_all(self, cls):
        if cls in self.items:
            del self.items[cls]