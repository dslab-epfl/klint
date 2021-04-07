from angr.exploration_techniques import ExplorationTechnique

class MergingTechnique(ExplorationTechnique):
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
            (merged, _, was_merged) = lowest[0].merge(*lowest[1:])
            if was_merged:
                new_state = merged
            else:
                new_state = lowest[0]
                simgr.stashes[self.deferred_stash].extend(lowest[1:])
        simgr.stashes[stash].append(new_state)
        return simgr