#!/usr/bin/python3

import math
import os
import pathlib
import statistics
import sys

import common


THIS_DIR = os.path.dirname(os.path.realpath(__file__))

if len(sys.argv) < 5:
  print('Args: <name> <latency percentile> <comparison percentile for scale> <nf folder name>*')
  sys.exit(1)

name = sys.argv[1]

if '.' in sys.argv[2]:
  perc = float(sys.argv[2])
else:
  perc = int(sys.argv[2]) # ensure the str doesn't contain a .0
perc_str = str(perc) + 'th percentile'
if perc == 50:
  perc_str = 'Median'
else:
  raise "only median for now due to bars"

perc_comp = float(sys.argv[3])

nfs = sys.argv[4:]

def lats_at_perc(lats, perc):
  return [(tput, common.percentile(ls, perc)) for (tput, ls) in lats]

numbers = {}
all_vals = []
max_tput = 0
lats_comp = []
for nf in nfs:
  nf_folder = THIS_DIR + '/' + nf

  lats_folder = pathlib.Path(nf_folder, 'latencies')
  lats = [(float(lat_file.name) / 1000, [float(l) / 1000.0 for l in lat_file.read_text().splitlines()]) for lat_file in lats_folder.glob('*')]
  lats = sorted(lats, key=lambda t: t[0])

  tput = lats[-1][0]

  tput_zeroloss_file = pathlib.Path(nf_folder, 'throughput-zeroloss')
  tput_zeroloss = float(tput_zeroloss_file.read_text()) if tput_zeroloss_file.exists() else math.inf

  lats_5 = lats_at_perc(lats, 5)
  lats_95 = lats_at_perc(lats, 95)
  lats_perc = lats_at_perc(lats, perc)
  lats_comp += lats_at_perc(lats, perc_comp)

  numbers[nf] = (lats_5, lats_95, lats_perc, lats_comp, tput_zeroloss, lats)
  max_tput = max(max_tput, tput)

all_lats_comp = [l for val in numbers.values()
                 for (t, l) in val[3]
                 for l in (t, l)]
median_lat_comp = statistics.median(all_lats_comp)

plt, ax, _ = common.get_pyplot_ax_fig()
ax.set_ylim(bottom=0, top=median_lat_comp * 3)
ax.set_xlim(0, 20.2) # just a little bit of margin to not hide the right side of the markers

# if any of the NFs are parallel, be clear the others are not
explicit_one_core = any('parallel' in nf for nf in nfs)

# We want a straight line up to tput_zeroloss, then a dashed line after that, so we draw 2 lines
# And we want the lines to be opaque while the dots should be non-opaque, for clarity, so we draw them separately
for nf, val in numbers.items():
  (lats_5, lats_95, lats, _, _, _) = val

  (color, label, marker) = common.get_color_label_marker(nf, explicit_one_core=explicit_one_core)

  y_5 = [l for (t, l) in lats_5]
  y_95 = [l for (t, l) in lats_95]
  all_x = [t for (t, l) in lats]
  all_y = [l for (t, l) in lats]

  ax.plot(all_x, all_y, color=color, alpha=0.4, linestyle='solid')
  ax.fill_between(all_x, y_5, all_y, color=color, alpha=0.2)
  ax.fill_between(all_x, all_y, y_95, color=color, alpha=0.2)
  ax.scatter(all_x, all_y, color=color, label=label, marker=marker)

plt.xlabel('Throughput (Gb/s)')
plt.ylabel(perc_str + ' latency (\u03BCs)')
plt.legend(loc='upper left', handletextpad=0.3, borderaxespad=0.08, edgecolor='white')

common.save_plot(plt, name)
print("Done! Plot is in plots/" + name + ".svg")


nf_click = numbers['bridge-click']
nf_dpdk = numbers['bridge-dpdk']
nf_us = numbers['bridge-tinynf']

label = None
plt, ax, _ = common.get_pyplot_ax_fig()
maxt = 0
for nf_comp in [nf_click, nf_dpdk]:
  if label is None:
    label = "Click"
  else:
    label = "DPDK"

  (color, label, marker) = common.get_color_label_marker(label)

  Ts = []
  T_diffs = []
  T_lows = []
  T_ups = []

  (_, _, _, _, _, all_lats_us) = nf_us
  (_, _, _, _, _, all_lats_comp) = nf_comp

  for t_lats_us, t_lats_comp in zip(all_lats_us, all_lats_comp):
    (t, lats_us) = t_lats_us
    (_, lats_comp) = t_lats_comp
    M1 = statistics.median(lats_us)
    M2 = statistics.median(lats_comp)

    o1 = statistics.variance(lats_us, M1)
    o2 = statistics.variance(lats_comp, M2)

    MSE = ((o1*o1)+(o2*o2))/2

    S = math.sqrt(2 * MSE / len(lats_us))

    tcl = 1.96

    MDIFF = M2 - M1

    lowlim = MDIFF - tcl * S
    uplim = MDIFF + tcl * S

    Ts.append(t)
    T_diffs.append(MDIFF)
    T_lows.append(lowlim)
    T_ups.append(uplim)
    maxt = max(t, maxt)

  ax.plot(Ts, T_diffs, color=color, alpha=0.4, linestyle='solid')
  ax.fill_between(Ts, T_lows, T_diffs, color=color, alpha=0.2)
  ax.fill_between(Ts, T_diffs, T_ups, color=color, alpha=0.2)
  ax.scatter(Ts, T_diffs, color=color, label=label, marker=marker)

ax.hlines(0, 0, maxt, colors=['gray'], alpha=0.5)
ax.set_xlim(0, maxt)

plt.xlabel('Throughput (Gb/s)')
plt.ylabel('Difference of means')
plt.legend(loc='upper left', handletextpad=0.3, borderaxespad=0.08, edgecolor='white')
common.save_plot(plt, "diffmeans")
print("Done! Plot is in plots/diffmeans-<label>.svg")
