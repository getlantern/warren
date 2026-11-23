"""Measure libtorrent's DHT on live Mainline, for cmd/dhtbench to compare.

Usage: python -I lt_bench.py WARMUP_SECONDS CONCURRENCY ROUTERS

ROUTERS is a comma-separated list of host:port bootstrap routers, the same
ones the warren node uses.

Warms up its routing table, printing {"t": "table", "at": s, "nodes": n}
every 5 seconds, then {"t": "ready"}. Then reads commands from stdin, one
JSON object per line:
  {"label": L, "targets": [hex, ...]}  immutable gets, CONCURRENCY at a time;
      prints {"t": "lookup", "label": L, "ms": ms, "found": bool} for each
      (ms -1 on a 60 s timeout), then {"t": "batch", "label": L}
  {"quit": true}
"""
import json
import sys
import time

import libtorrent as lt


def emit(o):
    print(json.dumps(o), flush=True)


warmup = float(sys.argv[1])
concurrency = int(sys.argv[2])
if concurrency < 1:
    sys.exit('CONCURRENCY must be at least 1')

routers = sys.argv[3]

s = lt.session({
    'listen_interfaces': '0.0.0.0:0',
    'enable_dht': True,
    'dht_bootstrap_nodes': routers,
    'enable_lsd': False,
    'enable_upnp': False,
    'enable_natpmp': False,
    'alert_mask': lt.alert_category.dht | lt.alert_category.status,
})


def table_size():
    s.post_dht_stats()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        s.wait_for_alert(200)
        for a in s.pop_alerts():
            if isinstance(a, lt.dht_stats_alert):
                return sum(b['num_nodes'] for b in a.routing_table)
    return -1


start = time.monotonic()
next_sample = 0.0
while time.monotonic() - start < warmup:
    at = time.monotonic() - start
    if at >= next_sample:
        emit({'t': 'table', 'at': round(at), 'nodes': table_size()})
        next_sample += 5
    time.sleep(0.2)
emit({'t': 'table', 'at': round(time.monotonic() - start), 'nodes': table_size()})
emit({'t': 'ready'})


def batch(label, targets):
    pending = {}  # target hex -> start time
    queue = list(targets)
    while queue or pending:
        while queue and len(pending) < concurrency:
            t = queue.pop(0)
            s.dht_get_immutable_item(lt.sha1_hash(bytes.fromhex(t)))
            pending[t] = time.monotonic()
        s.wait_for_alert(200)
        for a in s.pop_alerts():
            if isinstance(a, lt.dht_immutable_item_alert):
                t = str(a.target)
                if t in pending:
                    ms = round((time.monotonic() - pending.pop(t)) * 1000, 1)
                    found = bool(a.item)  # None (or empty) when not found
                    emit({'t': 'lookup', 'label': label, 'ms': ms, 'found': found})
        for t, began in list(pending.items()):
            if time.monotonic() - began > 60:
                emit({'t': 'lookup', 'label': label, 'ms': -1, 'found': False})
                del pending[t]
    emit({'t': 'batch', 'label': label})


for line in sys.stdin:
    cmd = json.loads(line)
    if cmd.get('quit'):
        break
    batch(cmd['label'], cmd['targets'])
