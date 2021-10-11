from angr.state_plugins.plugin import SimStatePlugin

marker_counter = 0

class MarkerPlugin(SimStatePlugin):
    def __init__(self, id=None):
        super().__init__()
        if id is None:
            self.increment_id()
        else:
            self.id = id

    @SimStatePlugin.memo
    def copy(self, memo):
        return MarkerPlugin(id=self.id)

    def merge(self, others, merge_conditions, common_ancestor=None):
        # Ideally we'd increment the ID here, but we don't actually know if the overall merge will succeed
        return True

    def increment_id(self):
        global marker_counter
        self.id = marker_counter
        marker_counter = marker_counter + 1
