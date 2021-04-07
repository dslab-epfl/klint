import angr
import claripy

# Version of SimState.merge that succeeds only if all plugins successfully merge, and returns the state or None
def merge_states(states):
    merge_flag = claripy.BVS("state_merge", 16)
    merge_conditions =  [merge_flag == b for b in range(len(states))]

    merged = states[0].copy()

    # same fix as in SimState.merge
    merged.history.parent = states[0].history

    for plugin_key in states[0].plugins.keys():
        # Some plugins have nothing to merge by design
        if plugin_key in ('regs', 'mem', 'scratch'):
            continue

        our_plugin = getattr(merged, plugin_key)
        other_plugins = [getattr(st, plugin_key) for st in states[1:]]
        
        # Callstack merely logs an error if there's an issue and never returns anything...
        if plugin_key == 'callstack':
            if any(o != our_plugin for o in other_plugins):
                return None
            continue

        if not our_plugin.merge(other_plugins, merge_conditions):
            # Memory returns false if nothing was merged, but that just means the memory was untouched
            if plugin_key in ('memory'):
                continue
            return None

    merged.add_constraints(merged.solver.Or(*merge_conditions))
    return merged

# Explores the state with the earliest instruction pointer first;
# if there are multiple, attempts to merge them.
# This is useful to merge states resulting from checks such as "if (a == X || a == Y)"
class MergingTechnique(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, deferred_stash='deferred'):
        super(MergingTechnique, self).__init__()
        self.deferred_stash = deferred_stash
        self.stop_points = {}

    def setup(self, simgr):
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []

    def step(self, simgr, stash='active', **kwargs):
        if stash != 'active':
            raise Exception("Sorry, haven't tested that")
        if len(simgr.stashes[stash]) != 1:
            raise Exception("Should not be possible, we ensure there is only one active state at a time...")

        simgr = simgr.step(stash=stash, **kwargs)
        if any(st.regs.rip.symbolic for st in simgr.stashes[stash]):
            raise Exception("Cannot handle symbolic instruction pointers")

        # Sort all states by instruction pointer
        simgr.split(from_stash=stash, to_stash=self.deferred_stash, limit=0)
        simgr.stashes[self.deferred_stash].sort(key=lambda s: s.regs.rip.args[0])

        # If there are none, then we are done (it rhymes!)
        if len(simgr.stashes[self.deferred_stash]) == 0:
            return simgr

        # If there are multiple states with the lowest, try and merge!
        lowest = []
        while len(simgr.stashes[self.deferred_stash]) > 0:
            current = simgr.stashes[self.deferred_stash].pop(0)
            if len(lowest) == 0 or current.regs.rip.structurally_match(lowest[0].regs.rip):
                lowest.append(current)
            else:
                simgr.stashes[self.deferred_stash].append(current)
                break
        if len(lowest) == 1:
            new_state = lowest[0]
        else:
            merged  = merge_states(lowest)
            if merged is None:
                new_state = lowest[0]
                simgr.stashes[self.deferred_stash].extend(lowest[1:])
            else:
                new_state = merged
        simgr.stashes[stash].append(new_state)
        return simgr
