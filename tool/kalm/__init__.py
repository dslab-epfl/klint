"""
Simplifies the use of angr for exhaustive symbolic execution.
"""

import angr

# Set to True to get some help while debugging...
DEBUG = False

# Register our spotters
from pyvex.lifting import register as pyvex_register
from .pyvex.rdmsr import RDMSRSpotter
pyvex_register(RDMSRSpotter, 'AMD64')

# Register our externals library
from .library import EmptyLibrary
EmptyLibrary().install()

# Provide to register plugins
# I can't find a way to make non-'default'-named presets work everywhere so let's just override it
from angr.sim_state import SimState
SimState.register_preset('default', angr.misc.plugins.PluginPreset())
def register_plugin(name, cls):
    SimState.register_default(name, cls, 'default')

# Register common angr plugins necessary for its proper functioning
register_plugin('callstack', angr.state_plugins.callstack.CallStack)
register_plugin('history', angr.state_plugins.history.SimStateHistory)
register_plugin('mem', angr.state_plugins.view.SimMemView)
register_plugin('regs', angr.state_plugins.view.SimRegNameView)
register_plugin('scratch', angr.state_plugins.scratch.SimStateScratch)
register_plugin('solver', angr.state_plugins.solver.SimSolver)

# Register the plugins we want
from .plugins import CastsPlugin, MetadataPlugin, PathPlugin, PciPlugin, SizesPlugin
from .memory import KalmMemory
register_plugin('casts', CastsPlugin)
register_plugin('metadata', MetadataPlugin)
register_plugin('path', PathPlugin)
register_plugin('pci', PciPlugin)
register_plugin('sizes', SizesPlugin)
register_plugin('sym_memory', KalmMemory) # Has to be named that way for angr to use it as default
register_plugin('fast_memory', KalmMemory) # angr needs this for some analyses to work

# Register the plugins we need even though we don't want them
from .plugins import FakeFilesystemPlugin
register_plugin('fs', FakeFilesystemPlugin)

# Help out with debugging errors...
import faulthandler
faulthandler.enable()

# Make randomness deterministic, just in case
import random
random.seed(10)

# Set up debug logging
import claripy
import logging
claripy.set_debug(DEBUG)
if DEBUG:
    logging.getLogger('angr').setLevel('DEBUG')
else:
    # Disable logs we don't care about
    logging.getLogger('cle.loader').setLevel('ERROR')
    logging.getLogger('cle.backends.externs').setLevel('ERROR')
    logging.getLogger('angr.engines.successors').setLevel('ERROR')
    logging.getLogger('angr.project').setLevel('ERROR')
