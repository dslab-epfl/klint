from angr.state_plugins.plugin import SimStatePlugin

class FakePlugin(SimStatePlugin):
    @SimStatePlugin.memo
    def copy(self, memo):
        return self

    def merge(self, others, merge_conditions, common_ancestor=None):
        return True

class FakeFilesystemPlugin(FakePlugin):
    def mount(self, path, mount):
        # Called by the POSIX plugin, which SimOS (the base class, not Linux) forcefully sets...
        pass