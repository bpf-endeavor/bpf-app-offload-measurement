#! /usr/bin/python3
import os
import matplotlib.pyplot as plt
import matplotlib
matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42


SOCKET = 'Socket'
SKSKB  = 'SK_SKB'
TC     = 'TC'
XDP    = 'XDP'

output = 'ebpf_overhead_on_latency.pdf'
config = {
        SOCKET: {
            'path': 'socket_duration_since_driver.txt',
            'color': 'black',
            'label': 'Socket',
            'median': 4015,
            'linestyle': '-',
            },
        TC: {
            'path': 'tc_duration_since_driver.txt',
            'color': 'orange',
            'label': 'TC',
            'median': 5003,
            'linestyle': ':',
            },
        XDP: {
            'path': 'xdp_duration_since_driver.txt',
            'color': 'tab:red',
            'label': 'XDP',
            'median': 4054,
            'linestyle': '--',
            },
        SKSKB: {
            'path': 'skskb_duration_since_driver.txt',
            'color': 'tab:green',
            'label': 'SK_SKB',
            'median': 4923,
            'linestyle': '-.',
            },
    }


def get_measures(path):
    tmp = []
    with open(path, 'r') as f:
        for line in f:
            v = line.split()[1]
            v = round(int(v) / 1000.0, 3)
            tmp.append(v)
    return tmp



figsize = [5, 2.5]
fig = plt.figure(figsize=figsize)
ax = fig.add_subplot(1,1,1)

# x_size = 10000 
# x = list(range(x_size))
for i, handle in enumerate([SOCKET,XDP,SKSKB,TC]):
    c = config[handle]
    d = get_measures(c['path'])
    # Skip the first 10K measurments
    d = d[10:]
    # assert len(d) > x_size, 'Number of samples are less than expected'
    # d = d[:x_size]
    # ax.plot(x, d, label=c['label'], color=c['color'], linewidth=0.9)
    # ax.set_title('Measurements for '+c['label'])
    # m = c['median']
    # ax.plot([0, x_size], [m, m], color='purple', label='Median of samples')
    ax.set_xlabel('Time to user-space (microseconds)')
    ax.set_ylabel('Empirical CDF')
    # ax.set_ylim([0, 20000])
    # ax.yaxis.set_ticks([0, 2500, 5000, 7500, 10000, 12500, 15000, 17500, 20000])
    # ax.xaxis.set_ticklabels([])
    ax.set_xlim([0, 20.000])
    ax.xaxis.set_ticks([0, 2.500, 5.000, 7.500, 10.000, 12.500, 15.000, 17.500, 20.000])

    ax.ecdf(d, label=c['label'], color=c['color'], linestyle=c['linestyle'])
    ax.grid(True)
    ax.legend()

plt.tight_layout()
outdir = './out'
if not os.path.isdir(outdir):
    os.mkdir(outdir)
output_file = os.path.join(outdir, output)
plt.savefig(output_file, dpi=300, bbox_inches='tight', pad_inches=0)
plt.show()
