from angr.state_plugins.plugin import SimStatePlugin

class DummyPlugin(SimStatePlugin):
    def __init__(self):
        SimStatePlugin.__init__(self)

    # Nothing; just ensures angr doesn't use plugins behind our back
