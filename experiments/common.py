#!/usr/bin/python3
# Common functions for graphing scripts

import math
import os

THIS_DIR = os.path.dirname(os.path.realpath(__file__))

def percentile(list, n):
  size = len(list)
  return sorted(list)[int(math.ceil((size * n) / 100)) - 1]

def get_pyplot_ax_fig(title=None, figsize=None):
  import matplotlib as mpl
  mpl.use('Agg') # avoid the need for an X server

  import matplotlib.pyplot as plt
  fig = plt.figure(figsize=figsize)
  # put the title inside the plot to save space
  if title is not None:
    fig.suptitle(title, y=0.85)

  ax = fig.add_subplot(1, 1, 1)
  # Remove top and right spines
  ax.spines['top'].set_visible(False)
  ax.spines['right'].set_visible(False)

  return (plt, ax, fig)

def get_color_label_marker(nf):
  if 'vigor-dpdk' in nf:
    return ('#4472C4', 'Vigor on DPDK (verified source)', 'x')
  if 'vigor-tinynf' in nf:
    return ('#28477E', 'Vigor on TinyNF (verified source)', 'X')
  if 'click' in nf:
    return ('#ED7D31', 'Click (unverified)', '^')
  if 'dpdk' in nf:
    return ('#7D31ED', 'Ours on DPDK (unverified)', 'v')
  return ('#70AD47', 'Ours on TinyNF (verified binary)', 'P') # P == filled plus

def save_plot(plt, name):
  plot_dir = THIS_DIR + '/plots/'
  os.makedirs(plot_dir, exist_ok=True)
  plt.savefig(plot_dir + name + '.pdf', bbox_inches='tight', pad_inches=0.025)
  print("Done! Plot saved to plots/" + name + ".pdf")
