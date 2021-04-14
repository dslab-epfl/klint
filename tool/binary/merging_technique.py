import angr
import claripy

# Version of SimState.merge that succeeds only if all plugins successfully merge, and returns the state or None
def merge_states(states):
    merge_flag = claripy.BVS("state_merge", 16)
    merge_conditions =  [merge_flag == b for b in range(len(states))]

    merged = states[0].copy()

    # same fix as in SimState.merge
    merged.history.parent = states[0].history

    all_plugins = set()
    for state in states:
        all_plugins.update(state.plugins.keys())

    for plugin in all_plugins:
        # Some plugins have nothing to merge by design
        if plugin in ('regs', 'mem', 'scratch'):
            continue

        our_plugin = getattr(merged, plugin)
        other_plugins = [getattr(st, plugin) for st in states[1:] if hasattr(st, plugin)]
        
        # Callstack merely logs an error if there's an issue and never returns anything...
        if plugin == 'callstack':
            if any(o != our_plugin for o in other_plugins):
                return None
            continue

        if not our_plugin.merge(other_plugins, merge_conditions):
            # Memory returns false if nothing was merged, but that just means the memory was untouched
            if plugin in ('memory'):
                continue
            print("Merge failed due to", plugin)
            return None

    merged.solver.add(merged.solver.Or(*merge_conditions))
    return merged

# Explores the state with the earliest instruction pointer first;
# if there are multiple, attempts to merge them.
# This is useful to merge states resulting from checks such as "if (a == X || a == Y)"
class MergingTechnique(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, deferred_stash='deferred', nomerge_stash='nomerge'):
        super(MergingTechnique, self).__init__()
        self.deferred_stash = deferred_stash
        self.nomerge_stash = nomerge_stash

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

        # If there were states that couldn't be merged before, just go with the first one
        if len(simgr.stashes[self.nomerge_stash]) > 0:
            simgr.stashes[stash].append(simgr.stashes[self.nomerge_stash].pop(0))
            return simgr

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
            print("Trying to merge! RIP=", lowest[0].regs.rip)
            merged  = merge_states(lowest)
            if merged is None:
                print("Oh well.")
                new_state = lowest[0]
                simgr.stashes[self.nomerge_stash].extend(lowest[1:])
            else:
                print("Yay!")
                new_state = merged
        simgr.stashes[stash].append(new_state)
        return simgr
