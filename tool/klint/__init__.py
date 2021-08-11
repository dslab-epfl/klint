"""
The Klint verification tool.
"""

# Register our plugins
import kalm
from .ghostmaps import GhostMapsPlugin
from .heap import HeapPlugin
kalm.register_plugin('maps', GhostMapsPlugin)
kalm.register_plugin('heap', HeapPlugin)