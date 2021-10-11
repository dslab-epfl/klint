import angr
import claripy
import math

from kalm import utils


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

    #print("Trying to merge", len(states), "states at", states[0].regs.rip)

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
            #print("    failed because of", plugin)
            return None
    #print("    done")
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
        self.state_graph_edges = []

    def record_fork(self, orig_id, forked_states):
        # Increment all IDs so we can distinguish those states even if one is the same reference as the original state (i.e., no copy was made)
        for st in forked_states:
            st.marker.increment_id()
        # Find the first divergent constraint
        # Note that in theory states could change their constraints beyond just appending, but in practice let's hope they don't...
        divergence_index = 0
        while all(s.solver.constraints[divergence_index] is forked_states[0].solver.constraints[divergence_index] for s in forked_states[1:]):
            divergence_index = divergence_index + 1
        # Record it all
        for st in forked_states:
            label = ''
            # Don't label the 2nd edge on a 2-state fork, it's obviously the opposite of the first edge
            if len(forked_states) != 2 or st is forked_states[0]:
                label = utils.pretty_print(st.solver.constraints[divergence_index])
            self.state_graph_edges.append((orig_id, st.marker.id, label))

    def record_merge(self, orig_ids, merged_state):
        # Increment the ID of the merged state to distinguish it
        merged_state.marker.increment_id()
        # Record the merge (no label)
        for id in orig_ids:
            self.state_graph_edges.append((id, merged_state.marker.id, ''))

    def graph_as_dot(self):
        # hardcoding line separators so the output is the same on all OSes
        result = 'digraph g {\n'
        for (src, dst, label) in self.state_graph_edges:
            result = result + '    ' + str(src) + ' -> ' + str(dst) + '[label="' + label + '"]\n'
        result = result + '}\n'
        return result

    def setup(self, simgr):
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []

    def step(self, simgr, stash='active', **kwargs):
        if stash != 'active':
            raise Exception("Sorry, haven't tested that")

        # Move all but one state to our deferred stash, so we can trivially know who the parent state of a fork is
        simgr.split(from_stash=stash, to_stash=self.deferred_stash, limit=1)

        # Store the ID of the original state, and its number of constraints, in case it forks and we need it later
        orig_id = simgr.stashes[stash][0].marker.id

        # Step! This might fork.
        simgr = simgr.step(stash=stash, **kwargs)

        # If we forked, record it
        if len(simgr.stashes[stash]) > 1:
            self.record_fork(orig_id, simgr.stashes[stash])

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

        if lowest[0].history.jumpkind == 'Ijk_Ret':
            # Do not try to merge states that have just returned from a function / external, it's pointless
            # They're usually split them for a reason (e.g. "in map"/"not in map")
            simgr.stashes[stash] = lowest
        else:
            # Try and merge them
            # Start by getting the plugins
            plugins = get_plugins(lowest)
            # Then triage
            triaged_piles = triage_for_merge(lowest, plugins)
            # Then merge individual piles
            for pile in triaged_piles:
                # Store the IDs of the states to merge for later (one will be used as the base for the merged state, so we need to store IDs before merging)
                orig_ids = [s.marker.id for s in pile]
                # Merge! Well, try, anyway
                merged = merge_states(pile, plugins)
                if merged is None:
                    simgr.stashes[stash].extend(pile)
                else:
                    # Record the merge
                    self.record_merge(orig_ids, merged)
                    # Store the merged state for the next time
                    simgr.stashes[stash].append(merged)

        return simgr
