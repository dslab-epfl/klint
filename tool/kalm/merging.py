import angr
import claripy
import math

# Version of SimState.merge that succeeds only if all plugins successfully merge
# Returns (merged_state, [deferred_states], [unmergeable_states])
def merge_states(states):
    if len(states) == 0:
        raise Exception("Zero states to merge??")

    # Filter out the states with a different callstack, to be merged later
    # This avoids the issue where there's a large number of states that could be merged but e.g. 1 is different
    # (without having to try and merge states pairwise, which takes too much time)
    deferred = []
    to_merge = [states[0]]
    for state in states[1:]:
        if state.callstack == states[0].callstack:
            to_merge.append(state)
        else:
            deferred.append(state)

    if len(to_merge) == 1:
        return (to_merge[0], [], [])
    print("Trying to merge", len(to_merge), "states")

    merge_flag = claripy.BVS("state_merge", math.ceil(math.log2(len(to_merge))))
    merge_conds = [(merge_flag == n) for n in range(len(to_merge))]

    merged = to_merge[0].copy()

    plugins = set()
    for state in to_merge:
        plugins = plugins | state.plugins.keys()
    plugins.remove("callstack") # we guaranteed it's the same earlier

    # Start by merging the solver so other plugins can rely on that, using our own function
    merged.solver.merge([st.solver for st in to_merge[1:]], merge_conds)
    plugins.remove("solver")

    for plugin in plugins:
        # Some plugins have nothing to merge by design
        if plugin in ('regs', 'mem', 'scratch'):
            continue

        our_plugin = getattr(merged, plugin)
        other_plugins = [getattr(st, plugin) for st in to_merge[1:]]

        if not our_plugin.merge(other_plugins, merge_conds):
            # Memory (of which register is a kind) returns false if nothing was merged, but that just means the memory was untouched
            if plugin in ('memory', 'registers'):
                continue
            print("Merge failed because of", plugin)
            return (to_merge[0], deferred, to_merge[1:])
    return (merged, deferred, [])


# Explores the state with the earliest instruction pointer first;
# if there are multiple, attempts to merge them.
# This is useful to merge states resulting from checks such as "if (a == X || a == Y)"
class MergingExplorationTechnique(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, deferred_stash='deferred', nomerge_stash='nomerge'):
        super().__init__()
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

        # Move all active states to our deferred stash
        simgr.split(from_stash=stash, to_stash=self.deferred_stash, limit=0)

        # If there were states that couldn't be merged before, go with the first one
        if len(simgr.stashes[self.nomerge_stash]) > 0:
            simgr.stashes[stash].append(simgr.stashes[self.nomerge_stash].pop(0))
            return simgr

        # If there are none, then we are done (it rhymes!)
        if len(simgr.stashes[self.deferred_stash]) == 0:
            return simgr

        # Sort all deferred states by instruction pointer
        def raiser(): raise Exception("Cannot handle symbolic instruction pointers")
        simgr.stashes[self.deferred_stash].sort(key=lambda s: s.regs.rip.args[0] if not s.regs.rip.symbolic else raiser())

        # Find the states with the lowest instruction pointer
        lowest = []
        while len(simgr.stashes[self.deferred_stash]) > 0:
            current = simgr.stashes[self.deferred_stash].pop(0)
            if len(lowest) == 0 or current.regs.rip.structurally_match(lowest[0].regs.rip):
                lowest.append(current)
            else:
                simgr.stashes[self.deferred_stash].append(current)
                break

        if 'SimProcedure' in lowest[0].history.recent_description:
            # Do not try to merge states that have just returned from an external call, it's pointless
            new_state = lowest[0]
            simgr.stashes[self.nomerge_stash].extend(lowest[1:])
        else:
            # Try and merge them
            (new_state, deferred, unmergeable) = merge_states(lowest)
            simgr.stashes[self.deferred_stash].extend(deferred)
            simgr.stashes[self.nomerge_stash].extend(unmergeable)

        simgr.stashes[stash].append(new_state)
        return simgr
