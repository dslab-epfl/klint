import angr
import claripy
import math
import time

from kalm import utils


def get_plugins(states):
    plugins = set()
    for state in states:
        plugins = plugins | state.plugins.keys()
    return plugins

def triage_for_merge(states, plugins, triage_ret_width):
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
    # Then triage based on the return value if needed
    if triage_ret_width is not None:
        ret_triaged = []
        for pile in triaged:
            groups = {}
            for st in pile:
                ret_val = utils.get_ret_val(st, triage_ret_width).cache_key
                groups.setdefault(ret_val, []).append(st)
            ret_triaged += list(groups.values())
        triaged = ret_triaged
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
            # Inspect always returns false
            if plugin == 'inspect':
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
    def __init__(self, ret_width: int | None = None, deferred_stash="deferred"):
        super().__init__()
        self.ret_width = ret_width
        self.deferred_stash = deferred_stash
        self.state_graph_nodes = {}
        self.state_graph_edges = []
        self.init_time = time.time()

    def record_step(self, orig_id, new_states):
        if len(new_states) == 0:
            # end of path, we've already set the ret when we knew it while stepping
            return
        node_descr = new_states[0].history.recent_description
        if len(new_states) == 1 and 'SimProcedure' not in node_descr:
            # not interesting
            return
        # Increment IDs so we can distinguish those states even if one is the same reference as the original state (i.e., no copy was made)
        for st in new_states:
            st.marker.increment_id()
        # Try and get a proper label for the node
        node_label = ''
        if node_descr.startswith("<IRSB"):
            node_label = 'Branch: ' + node_descr.split(' ')[2][:-1] # remove the ':' at the end; format is '<IRSB from 0xaaaa: ...>'
        elif node_descr.startswith("<SimProcedure"):
            node_label = node_descr.split(' ')[1] # procedure name else: print("???", node_descr)
        if node_label != '':
            node_label += '\n'
        node_label += str(round(time.time() - self.init_time, 1)) + "s"
        self.state_graph_nodes[orig_id] = node_label
        # Find the first divergent constraint if we have >1 state
        # Note that in theory states could change their constraints beyond just appending, but in practice let's hope they don't...
        if len(new_states) > 1:
            divergence_index = 0
            while all(s.solver.constraints[divergence_index] is new_states[0].solver.constraints[divergence_index] for s in new_states[1:]):
                divergence_index = divergence_index + 1
            # If we have 2 forked states and the constraint is ~C in state0 and C in state1, invert them, for readability
            if len(new_states) == 2 and new_states[0].solver.constraints[divergence_index].op == 'Not' and \
               new_states[0].solver.constraints[divergence_index].args[0] is new_states[1].solver.constraints[divergence_index]:
                new_states = [new_states[1], new_states[0]]
        # Record it all
        for st in new_states:
            label = ''
            # Don't label if there's a single new state or if it's the 2nd edge on a 2-state fork (in the latter case, it's obviously the opposite of the first edge)
            if len(new_states) != 1 and (len(new_states) != 2 or st is new_states[0]):
                label = utils.pretty_print(st.solver.constraints[divergence_index])
            self.state_graph_edges.append((orig_id, st.marker.id, label))

    def record_merge(self, orig_ids, merged_state):
        # Increment the ID of the merged state to distinguish it
        merged_state.marker.increment_id()
        # Record the merge (no label)
        for id in orig_ids:
            self.state_graph_edges.append((id, merged_state.marker.id, ''))

    def graph_as_dot(self):
        # First, filter edges so we don't show nodes without labels; if we did everything right that's also the set of nodes with exactly 1 entry and 1 exit
        edges = []
        for (src, dst, label) in self.state_graph_edges:
            if src not in self.state_graph_nodes:
                if len([s for (s,d,l) in self.state_graph_edges if src == d]) == 1:
                    continue
            if dst not in self.state_graph_nodes:
                # Find where the edge should end instead
                end = [d for (s,d,l) in self.state_graph_edges if dst == s]
                if len(end) == 1:
                    dst = end[0]
            edges.append((src, dst, label))
        # hardcoding line separators so the output is the same on all OSes
        result = 'digraph g {\n'
        # Print edges
        for (src, dst, label) in edges:
            # use xlabel (Xternal label) so 'dot' will not put the label inbetween two edges which is confusing
            result = result + '    ' + str(src) + ' -> ' + str(dst) + ' [xlabel="' + label + '"]\n'
        # Mark end states with a double border
        for node in set(d for (s,d,l) in edges) - set(s for (s,d,l) in edges):
            result = result + '    ' + str(node) + ' [peripheries=2]\n'
        # Mark nodes with their labels when available
        for (n, l) in self.state_graph_nodes.items():
            result = result + '    ' + str(n) + ' [label="' + l + '"]\n'
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

        # Store the ID of the original state, and its number of constraints, for later recording
        orig_id = simgr.stashes[stash][0].marker.id

        # Step! This might fork.
        simgr = simgr.step(stash=stash, **kwargs)

        # Record the step
        self.record_step(orig_id, simgr.stashes[stash])

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

        # Do not try to merge states that have just returned from a function / external, it's pointless
        # They're usually split them for a reason (e.g. "in map"/"not in map")
        # But do keep track of the returned value in case it's the last one
        if lowest[0].history.jumpkind == 'Ijk_Ret':
            simgr.stashes[stash] = lowest
            st = lowest[0]
            if self.ret_width == 0:
                self.state_graph_nodes[st.marker.id] = 'ret'
            else:
                result = utils.get_ret_val(st, self.ret_width)
                self.state_graph_nodes[st.marker.id] = 'ret ' + utils.pretty_print(result)
            return simgr

        # Check whether we should triage based on the return value
        triage_ret_width = None
        try:
            lowest_block = lowest[0].project.factory.block(lowest[0].regs.rip.args[0])
        except angr.errors.SimEngineError:
            # rip points to an external call (using try here is kind of dirty though...)
            lowest_block = None
        if lowest_block and len(lowest_block.vex.constant_jump_targets) == 0:
            # if we didn't get a hint for the ret width, use the maximum
            triage_ret_width = self.ret_width or lowest[0].arch.bits

        # Try and merge them
        # Start by getting the plugins
        plugins = get_plugins(lowest)
        # Then triage
        triaged_piles = triage_for_merge(lowest, plugins, triage_ret_width)
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
