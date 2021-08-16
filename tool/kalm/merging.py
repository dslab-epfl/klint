import angr
import claripy
import math

# Specialized function to merge solvers that are expected to have a lot in common
# Anything in common is kept as-is, the rest is added as (merge_cond implies noncommon_constraint)
# This doesn't help perf, but massively helps readability
def merge_solvers(this_solver, other_solvers, merge_conds):
    new_underlying = this_solver._solver.blank_copy()
    divergence_index = 0
    min_length = min(len(this_solver.constraints), *[len(s.constraints) for s in other_solvers])
    while divergence_index < min_length:
        for solver in other_solvers:
            if this_solver.constraints[divergence_index] is not solver.constraints[divergence_index]:
                break
        else:
            new_underlying.add(this_solver.constraints[divergence_index])
            divergence_index = divergence_index + 1
            continue
        break
    for i, solver in enumerate([this_solver] + other_solvers):
        for extra in solver.constraints[divergence_index:]:
            new_underlying.add(~merge_conds[i] | extra)
    new_underlying.add(claripy.Or(*merge_conds))
    this_solver._stored_solver = new_underlying

# Version of SimState.merge that succeeds only if all plugins successfully merge, and returns the state or None
def merge_states(states):
    if len(states) == 0:
        raise Exception("Zero states to merge??")
    if len(states) == 1:
        return states[0]
    print("Trying to merge", len(states), "states")

    merge_flag = claripy.BVS("state_merge", math.ceil(math.log2(len(states))))
    merge_conds = [(merge_flag == n) for n in range(len(states))]

    merged = states[0].copy()

    plugins = set()
    for state in states:
        plugins = plugins | state.plugins.keys()

    # Start by merging the solver so other plugins can rely on that, using our own function
    plugins.remove("solver")
    merge_solvers(merged.solver, [st.solver for st in states[1:]], merge_conds)

    for plugin in plugins:
        # Some plugins have nothing to merge by design
        if plugin in ('regs', 'mem', 'scratch'):
            continue

        our_plugin = getattr(merged, plugin)
        other_plugins = [getattr(st, plugin) for st in states[1:]]

        # Callstack merely logs an error if there's an issue and never returns anything...
        if plugin == 'callstack':
            if any(op != our_plugin for op in other_plugins):
                print("Merge failed because of callstack")
                return None
            continue

        if not our_plugin.merge(other_plugins, merge_conds):
            # Memory (of which register is a kind) returns false if nothing was merged, but that just means the memory was untouched
            if plugin in ('memory', 'registers'):
                continue
            print("Merge failed because of", plugin)
            return None
    return merged


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

        # Try and merge them
        # Do not try to merge the final states, it'll fail 99% of the time
        if lowest[0].history.jumpkind == 'Ijk_Ret' and lowest[0].callstack.ret_addr == 0:
            new_state = None
        else:
            new_state = merge_states(lowest)

        if new_state is None:
            new_state = lowest[0]
            simgr.stashes[self.nomerge_stash].extend(lowest[1:])

        simgr.stashes[stash].append(new_state)
        return simgr
