import angr
import claripy
from angr.state_plugins.plugin import SimStatePlugin
import executors.binary.utils as utils
import copy

# Optimization: objects are compared structurally instead of with the solver, which might cause spurious failures
# (this does not work unless ghost maps are doing the "use existing items if possible in get" optimization)

class Metadata(SimStatePlugin):
    merge_funcs = {}

    # func_across takes as input ([states], [objs], ancestor_state)
    #                and returns [(ID, [objs], lambda (state, [meta]): None or [meta] to overwrite)]
    #                fixed-point if the returned [(ID, [objs])] is a superset of the previous one
    # func_one takes as input ([states], obj, ancestor_state)
    #             and returns (meta)
    #             fixed-point if meta is structurally equal to ancestor_state's
    # Regardless of whether this method is called for a given class,
    # metadata that is not present in the ancestor state, regardless of value, will be discarded.
    # If this method is not called for a given class,
    # metadata of that class is kept if it is structurally equal in all states and discarded otherwise
    @staticmethod
    def set_merge_funcs(cls, func_across, func_one):
        if cls in Metadata.merge_funcs and Metadata.merge_funcs[cls] != (func_across, func_one):
            raise "Cannot change merge functions once set"
        Metadata.merge_funcs[cls] = (func_across, func_one)


    def __init__(self, items=None, merge_across_results=None):
        SimStatePlugin.__init__(self)
        self.items = items or {}
        self.merge_across_results = merge_across_results or {}


    def set_state(self, state):
        SimStatePlugin.set_state(self, state)


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
        one_results_equal = True

        merged_items = {}
        across_results = {}
        for (cls, items) in self.items.items():
            if cls not in ancestor_state.metadata.items:
                # Ignore any metadata class that was not already in the ancestor state
                continue
            # Ignore any metadata key that was not already in the ancestor state
            common_keys = [k for (k, v) in items if ancestor_state.metadata._get(cls, k) != []]

            merged_items[cls] = []
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
                    old_value = ancestor_state.metadata.get(cls, key)
                    merged_value = Metadata.merge_funcs[cls][1]([self.state] + other_states, key, ancestor_state)
                    one_results_equal = one_results_equal and utils.structural_eq(old_value, merged_value)
                    merged_items[cls].append((key, merged_value))
            else:
                # No merge function, keep all of the ones that are referentially equal, discard the others
                for key in common_keys:
                    value = self.get(cls, key)
                    if all(utils.structural_eq(other.metadata.get(cls, key), value) for other in other_states):
                        merged_items[cls].append((key, value))

        # As the doc states, fixpoint if all merges resulted in the old result and the across_results are a superset
        reached_fixpoint = one_results_equal and all(len(items) == 0 for items in across_previous_results.values())
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


    def _get(self, cls, key):
        if cls not in self.items:
            return []
        return [(k, v) for (k, v) in self.items[cls] if (k.structurally_match(key) if k is not None else k is key)]


    def get(self, cls, key, default=None):
        results = self._get(cls, key)
        if len(results) == 0:
            if default is None:
                raise ("No metadata for key: " + str(key) + " of class: " + str(cls))
            else:
                self.set(key, default)
                return default

        if len(results) > 1:
            raise ("More than one matching metadata of type " + str(cls) + " for key: " + str(key))

        return results[0][1]


    def get_all(self, cls):
        return self.items.get(cls, [])


    def set(self, key, value, override=False):
        cls = type(value)
        results = self._get(cls, key)
        if len(results) > 1:
            raise ("More than one existing metadata of type " + str(cls) + " for key: " + str(key))

        has_already = len(results) == 1
        if has_already:
            if override:
                self.items[cls] = [(k, v) for (k, v) in self.items[cls] if k is not results[0][0]] # using remove() tests by value, which ends up converting claripy ASTs to bool, which they don't like
            else:
                raise ("There is already metadata of type " + str(cls) + " for key: " + str(key) + ", namely " + str(results))

        if override and not has_already:
            raise ("There is no metadata of type " + str(cls) + " to override for key: " + str(key))

        if cls not in self.items:
            self.items[cls] = []

        self.items[cls].append((key, value))


    def remove(self, cls, key):
        self.items[cls] = [(k, v) for (k, v) in self.items[cls] if k is not key] # same comment as in set


    def remove_all(self, cls):
        if cls in self.items:
            del self.items[cls]
