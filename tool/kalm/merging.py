import angr
import claripy

# Specialized function to merge solvers that are expected to have a lot in common
# Anything in common is kept as-is, the rest is added as (merge_cond implies noncommon_constraint)
def merge_solvers(this_solver, other_solver, merge_conds):
    divergence_index = 0
    new_underlying = this_solver._solver.blank_copy()
    while divergence_index < min(len(this_solver.constraints), len(other_solver.constraints)) and this_solver.constraints[divergence_index] is other_solver.constraints[divergence_index]:
        new_underlying.add(this_solver.constraints[divergence_index])
        divergence_index = divergence_index + 1
    for this_extra in this_solver.constraints[divergence_index:]:
        new_underlying.add(~merge_conds[0] | this_extra)
    for other_extra in other_solver.constraints[divergence_index:]:
        new_underlying.add(~merge_conds[1] | other_extra)
    new_underlying.add(claripy.Or(*merge_conds))
    this_solver._stored_solver = new_underlying

# Version of SimState.merge that succeeds only if all plugins successfully merge, and returns the state or None
def merge_states(states):
    candidate = states.pop()
    failed = []
    while len(states) > 0:
        merged = candidate.copy()
        merge_flag = claripy.BVS("state_merge", 16)
        merge_conds = [(merge_flag == 0), (merge_flag == 1)]
        other = states.pop()
        plugins = list(merged.plugins.keys() | other.plugins.keys())
        # Start by merging the solver so other plugins can rely on that, using our own function
        plugins.remove("solver")
        merge_solvers(merged.solver, other.solver, merge_conds)
        for plugin in plugins:
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

            if not our_plugin.merge([other_plugin], merge_conds):
                # Memory (of which register is a kind) returns false if nothing was merged, but that just means the memory was untouched
                if plugin in ('memory', 'registers'):
                    continue
                #print("Merge failed because of", plugin)
                break
        else:
            # no break -> all good
            print("MERGE SUCCESS", merge_conds)
            candidate = merged
            continue
        # did break -> some plugin couldn't be merged
        print("MERGE FAIL", merge_conds)
        failed.append(other)
    return (candidate, failed)


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
        # Do not try to merge the final states, it'll fail 99% of the time
        if lowest[0].history.jumpkind == 'Ijk_Ret' and lowest[0].callstack.ret_addr == 0:
            new_state, rest = lowest[0], lowest[1:]
        else:
            new_state, rest = merge_states(lowest)
        simgr.stashes[self.deferred_stash].extend(rest)
        simgr.stashes[stash].append(new_state)
        return simgr
