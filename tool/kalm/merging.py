import angr
import claripy

# Version of SimState.merge that succeeds only if all plugins successfully merge, and returns the state or None
def merge_states(states):
    candidate = states.pop(0)
    while len(states) > 0:
        merged = candidate.copy()
        merge_flag = claripy.BVS("state_merge", 16)
        merge_conds = [(merge_flag == 0), (merge_flag == 1)]
        other = states.pop()
        for plugin in other.plugins.keys():
            # Some plugins have nothing to merge by design
            if plugin in ('regs', 'mem', 'scratch'):
                continue

            our_plugin = getattr(merged, plugin)
            other_plugin = getattr(other, plugin)

            # Callstack merely logs an error if there's an issue and never returns anything...
            if plugin == 'callstack':
                if other_plugin != our_plugin:
                    #print("Merge failed because of callstack?!?")
                    break
                continue

            # TODO what could we pass as ancestor here?
            if not our_plugin.merge([other_plugin], merge_conds):
                # Memory (of which register is a kind) returns false if nothing was merged, but that just means the memory was untouched
                if plugin in ('memory', 'registers'):
                    continue
                #print("Merge failed because of", plugin)
                break
        else:
            # no break -> all good
            merged.solver.add(claripy.Or(*merge_conds))
            candidate = merged
            continue
        # did break -> some plugin couldn't be merged, put other back on the list
        states.append(other)
        return (candidate, states)
    # states is empty, we merged everything, yay!
    return (candidate, states)


# Explores the state with the earliest instruction pointer first;
# if there are multiple, attempts to merge them.
# This is useful to merge states resulting from checks such as "if (a == X || a == Y)"
class MergingExplorationTechnique(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, deferred_stash='deferred'):
        super().__init__()
        self.deferred_stash = deferred_stash

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
        new_state, rest = merge_states(lowest)
        simgr.stashes[self.deferred_stash].extend(rest)
        simgr.stashes[stash].append(new_state)
        return simgr
