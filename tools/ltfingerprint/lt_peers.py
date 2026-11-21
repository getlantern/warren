"""Run a few libtorrent DHT nodes on loopback next to a Go observer.

Usage: python -I lt_peers.py OBSERVER_PORT [SECONDS]

Prints "PORTS p1 p2 ..." once the nodes listen, then exercises the DHT client
side (put, get, get_peers, announce) so the observer sees every query type.
"""
import os
import sys
import time

import libtorrent as lt

observer = ('127.0.0.1', int(sys.argv[1]))
seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 20

sessions = []
for _ in range(4):
    s = lt.session({
        'listen_interfaces': '127.0.0.1:0',
        'outgoing_interfaces': '127.0.0.1',
        'enable_dht': True,
        'dht_bootstrap_nodes': '',
        'enable_lsd': False,
        'enable_upnp': False,
        'enable_natpmp': False,
        'dht_restrict_routing_ips': False,
        'dht_restrict_search_ips': False,
        'dht_enforce_node_id': False,
        'dht_block_ratelimit': 1000,
    })
    sessions.append(s)

deadline = time.monotonic() + 10
while any(s.listen_port() == 0 for s in sessions):
    if time.monotonic() > deadline:
        sys.exit('libtorrent did not start listening')
    time.sleep(0.05)

ports = [s.listen_port() for s in sessions]
for i, s in enumerate(sessions):
    s.add_dht_node(observer)
    s.add_dht_node(('127.0.0.1', ports[(i + 1) % len(ports)]))
print('PORTS ' + ' '.join(map(str, ports)), flush=True)
print('VERSION ' + lt.__version__, flush=True)

time.sleep(4)
s = sessions[0]
target = s.dht_put_immutable_item(b'fingerprint probe value')
s.dht_get_immutable_item(target)
info_hash = lt.sha1_hash(os.urandom(20))
s.dht_get_peers(info_hash)
s.dht_announce(info_hash, 6881, 0)

time.sleep(max(0, seconds - 4))
for s in sessions:
    s.pause()
