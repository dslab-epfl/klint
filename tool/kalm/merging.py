import angr
import claripy
import math

def get_plugins(states):
    plugins = set()
    for state in states:
        plugins = plugins | state.plugins.keys()
    return plugins

def triage_for_merge(states, plugins):
    # Triage the callstack first
    triaged = [[states[0]]]
    for state in states[1:]:
        for candidate in triaged:
            if candidate[0].callstack == state.callstack:
                candidate.append(state)
                break
        else:
            triaged.append([state])
    # We guarantee it's literally the same among triaged piles, so no need to look at it further
    plugins.remove("callstack")
    # Then triage using plugins
    def plugin_triage(piles, plugin):
        # Design note: this really screams for static methods on plugins instead...
        if not hasattr(getattr(piles[0][0], plugin), 'merge_triage'):
            return piles
        final_piles = []
        for pile in piles:
            if len(pile) == 1:
                # No need to bother with single-item piles
                final_piles.append(pile)
                continue
            our_plugin = getattr(pile[0], plugin)
            plugin_triaged = our_plugin.merge_triage([getattr(st, plugin) for st in pile[1:]])
            # plugin.state is a weakproxy so we undo it, see https://stackoverflow.com/a/62144308
            final_piles.extend([[plugin.state.__repr__.__self__ for plugin in plugin_pile] for plugin_pile in plugin_triaged])
        return final_piles
    for plugin in plugins:
        triaged = plugin_triage(triaged, plugin)
    return triaged

# Version of SimState.merge that succeeds only if all plugins successfully merge
# Returns merged_state or None
def merge_states(states, plugins):
    assert len(states) != 0, "Zero states to merge??"

    # Return None for a single state because this logically means "could not merge", i.e. "don't try again next time"
    if len(states) == 1:
        return None

    #if len(states) >= 50:
        # Don't even bother trying, odds of succeeding are slim given our current heuristics
        #print("Not bothering to try a merge with", len(states), "states")
        #return None

    print("Trying to merge", len(states), "states at", states[0].regs.rip)

    merge_flag = claripy.BVS("state_merge", math.ceil(math.log2(len(states))))
    merge_conds = [(merge_flag == n) for n in range(len(states))]
    merged = states[0].copy()

    # Start by merging the solver so other plugins can rely on that
    merged.solver.merge([st.solver for st in states[1:]], merge_conds)

    for plugin in plugins:
        # We merged that already
        if plugin == 'solver':
            continue
        # Some plugins have nothing to merge by design
        if plugin in ('regs', 'mem', 'scratch'):
            continue
        our_plugin = getattr(merged, plugin)
        other_plugins = [getattr(st, plugin) for st in states[1:]]
        if not our_plugin.merge(other_plugins, merge_conds):
            # Memory (of which registers is a kind) returns false if nothing was merged, but that just means the memory was untouched
            if plugin in ('memory', 'registers'):
                continue
            print("    failed because of", plugin)
            return None
    print("    done")
    return merged


# Explores the state with the earliest instruction pointer first;
# if there are multiple, attempts to merge them.
# This is useful to merge states resulting from checks such as "if (a == X || a == Y)"
# Has two stashes:
# - 'deferred' for states it hasn't looked at yet
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

        simgr = simgr.step(stash=stash, **kwargs)

        # Move all active states to our deferred stash
        simgr.stashes[self.deferred_stash].extend(simgr.stashes[stash])
        simgr.stashes[stash] = []

        # If there are none, then we are done (it rhymes!)
        if len(simgr.stashes[self.deferred_stash]) == 0:
            return simgr

        # Sort all deferred states by instruction pointer
        def raiser(): raise Exception("Cannot handle symbolic instruction pointers")
        simgr.stashes[self.deferred_stash].sort(reverse=True, key=lambda s: s.regs.rip.args[0] if not s.regs.rip.symbolic else raiser())

        # Find the states with the lowest instruction pointer
        lowest = []
        while len(simgr.stashes[self.deferred_stash]) > 0:
            current = simgr.stashes[self.deferred_stash].pop()
            if len(lowest) == 0 or current.regs.rip.structurally_match(lowest[0].regs.rip):
                lowest.append(current)
            else:
                simgr.stashes[self.deferred_stash].append(current)
                break

        if 'SimProcedure' in lowest[0].history.recent_description:
            # Do not try to merge states that have just returned from an external call, it's pointless
            # The call split them for a reason (e.g. "in map"/"not in map")
            simgr.stashes[stash] = lowest
        else:
            # Try and merge them
            # Start by getting the plugins
            plugins = get_plugins(lowest)
            # Then triage
            triaged_piles = triage_for_merge(lowest, plugins)
            merged_states = []
            # Then merge individual piles
            for pile in triaged_piles:
                merged = merge_states(pile, plugins)
                if merged is None:
                    simgr.stashes[stash].extend(pile)
                else:
                    simgr.stashes[stash].append(merged)

        return simgr
