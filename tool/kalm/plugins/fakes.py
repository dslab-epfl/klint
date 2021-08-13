from angr.state_plugins.plugin import SimStatePlugin

class FakeFilesystemPlugin(SimStatePlugin):
    @SimStatePlugin.memo
    def copy(self, memo):
        return FakeFilesystemPlugin()

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True

    def mount(self, path, mount):
        # Called by the POSIX plugin, which SimOS (the base class, not Linux) forcefully sets...
        pass