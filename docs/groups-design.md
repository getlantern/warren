# Private groups (design, not built)

A **group** is a set of devices that share a secret, find each other through
the DHT without anyone else learning who they are, connect only to each
other, and share content (video first) by swarming: a member fetches a file
from every member that has it at once, verified piece by piece.

This is a fresh design for the Go stack, informed by the Rust warren and
Murmur channels but not wire-compatible with them. It is a library (package
`group`) for any app on warren, not Murmur's app logic.

## Goals

- **Outsiders learn nothing.** Without the group secret, nobody can tell a
  group exists, who is in it, what it shares, or link a member's activity
  across groups or across time. The DHT sees only rotating, keyed, opaque
  targets and encrypted values.
- **Only members connect.** A device that isn't on the roster can't open a
  session to a member, so it can't read even metadata.
- **Removal is real.** A removed member can't read content added after its
  removal, and can't find the group again.
- **Fast and light.** Swarming saturates the members' combined upload; a
  phone can stream a video as it arrives; idle membership costs a few DHT
  packets a minute and no memory to speak of.
- **Reusable.** The library knows groups, members, a signed log per member,
  and content blobs. Chat, comments, titles and thumbnails are app entries
  and metadata it carries opaquely.

Non-goals for v1: groups of thousands (see *Scale*), anonymity against a
member (members see each other's addresses when they connect), and
deniability.

## What Rust warren did, and what changes

Rust channels (`crates/warren/src/channel.rs`, `session.rs`, `roster.rs`;
Murmur `core/src/lib.rs`):

- discovery topic `BLAKE3(domain ‖ psk ‖ epoch)`, a plain hash, members
  announcing their node IDs under it in the clear;
- a separate content key, so a blind mirror serves ciphertext it can't read;
- 64 KiB chunks named by BLAKE3, swarmed from up to 5 sources, rarest-first;
- a signed roster folded from a founder's genesis;
- an unencrypted invite carrying the keys.

Gaps this design closes:

| Rust | Here |
|---|---|
| Serving checks no membership: anyone who learns a member's node ID reads its feed metadata | Every session is authenticated to the roster before anything is served (*Sessions*) |
| One device feed key across all channels, linkable | A device key per group (*Identity*) |
| Members announce IPs in the clear under the topic | Members are reached through warren's signaling: records hold an encrypted key, holders and relays hide addresses (*Discovery*) |
| Titles, chat, thumbnails plaintext | All metadata encrypted (*Content*) |
| No rotation; a removed member reads everything | Group key epochs rotate on removal (*Removal*) |
| Topic a plain hash of the PSK | HKDF-derived keys, HMAC topics (*Keys*) |

## Keys

A group is created from a random 32-byte **group secret** `G`. It locates
and protects the group's rendezvous, and nothing more: content keys never
derive from it, since every invite carries it. Keys derived from `G` with
HKDF-SHA256 (labels abbreviated):

| Key | Derivation | Use |
|---|---|---|
| `dirKey` | `HKDF(G, "warren/group/v1 directory")` | derives each period's directory keys and salts (*Discovery*) |
| `dirSeal` | `HKDF(G, "… directory seal")` | encrypts directory entries |
| `rosterKey` | `HKDF(G, "… roster")` | encrypts roster operations in transit |

**Epoch keys** wrap content keys (*Content*, *Logs*). `epochKey[0]` is random,
made by the founder; every later one is made on a rekey (*Removal*). Epoch
keys travel only sealed to individual members' keys (in `add` and `rekey`
operations), never derivable from `G`, so an invite holder or a blind mirror
can't read content.

**Periods** are one hour. Everything a period publishes (the directory's
signing key, its salts, members' rendezvous keys) derives from `dirKey` or
the member's key plus the period, so nothing visible on the DHT repeats
across hours.

**Removal replaces `G` too** (*Removal*): a removed member knows the old `G`,
so it could still read the directory. After a rekey the remaining members
move to `G'` and stop using the old directory.

## Identity

Each device holds a separate ed25519 **member key** per group, generated on
join and never reused across groups. It signs the device's roster
operations, directory entries and log entries, and peers check it inside
every session. It never appears on the DHT.

On the DHT the device is reached under a **rendezvous key** instead: a fresh
ed25519 key each period, `seed = HKDF(memberSecret ‖ G, "rendezvous" ‖ period)`,
listened under with `endpoint.Listen`. Warren's signaling records are signed
by the listener key and stored by holders next to the listener's address,
so a holder sees only a key that changes every hour and means nothing
without `G`.

A device in several groups listens under one rendezvous key per group. If
those listeners share one socket, a holder of two of them could notice two
keys behind one address in the same hour, so each group's listener should
use its own socket (its own port), at the cost of a socket and keepalives per
group.

## Roster

The roster is a set of operations signed by member keys, kept by members
(not on the DHT) and exchanged sealed under `rosterKey`:

- `genesis` (founder key, group name, shard count, `epochKey[0]` sealed to
  the founder);
- `add` (member key, display name, role, and the current `G` and every epoch
  key so far, each sealed to the new member) by an admin;
- `remove` (member key, and the highest sequence number of its log the
  remover has seen, see *Logs*) by an admin;
- `rekey` (see *Removal*) by an admin.

Operations carry a Lamport clock and their causal parents (the hashes of the
latest operations the author had seen). Folding is deterministic: operations
are applied in causal order, concurrent ones ordered by hash, and each is
checked **when applied**: it counts only if its author is an admin at that
point in the fold. So of two admins removing each other concurrently, the
removal applied first stands and the second is ignored, since its author is
no longer an admin. A `remove` of the last remaining admin is ignored, so a
group always keeps one. **Remove wins** over a concurrent `add` of the same
key. Members exchange operations they lack at the start of every session
(*Sessions*), so the roster converges by gossip.

Roles in v1: `admin` (add, remove, rekey) and `member` (post, fetch).

## Discovery

Members find each other's **rendezvous keys** through the group directory,
then reach each other with warren's existing Connect-by-key (encrypted
signaling, holders, relays, NAT punching). No member's address or member key
is ever published under a group topic.

The **directory** is a set of BEP 44 mutable items, one per shard, rotated
each period:

- signing key: `seed = HKDF(dirKey, "directory key" ‖ period)`, so the `k`
  every put and reply carries changes every hour;
- salt: `HMAC(dirKey, "directory salt" ‖ period ‖ shard)`;
- value, sealed under `dirSeal`, up to ~900 bytes: about 20 **entries**, each
  a member's current rendezvous key and a last-seen time, signed by that
  member's key.

A member that comes online reads the current and previous period's shards,
keeps only entries signed by a key on its roster, merges, adds its own entry,
and puts back the shard its member key hashes to (with CAS on the sequence
number, retrying on conflict), repeating every half period. It calls the
members it finds with `endpoint.Connect`. Once one session is up, roster,
rendezvous keys and peer lists flow over sessions, so the directory matters
mostly for a cold start or after a long absence.

**Shards:** about 20 entries fit in one, so the genesis sets the shard count
from the expected size: three shards for a group of 50.

**A leaked `G`** (a leaked invite, or a removed member before the rekey
reaches everyone) can't forge entries, since readers check each entry's
member signature against the roster, but it can overwrite shards (the
directory's signing key derives from `G`) and so disrupt cold-start
discovery until the next rekey. Members recover from cached peers and the
invite's bootstrap hints, and an admin can rekey to cut the holder off.

## Sessions

A session is a hysteria2 connection between two members over a punched
path (`endpoint.Connect`, `transport/hy2`), so it inherits migration, stall
recovery and memory caps.

- **Authorization before anything is served.** The callee's listener (one
  per group, see *Identity*) admits a caller only if the caller's rendezvous
  key is one it has seen in a roster-signed directory entry or a member's
  peer list. Then, inside the encrypted session, each side signs the
  session's secret with its **member key**, and each checks the other's
  member key is on its roster. Nothing is served before both checks pass.
  Warren needs two changes for this: an endpoint listening under several
  keys at once (today the DHT node holds a single listener), and `Authorize`
  told which listener key was called.
- **A newer roster than the callee's** (a member added since the callee last
  synced): the caller may present the signed `add` chain first; the callee
  verifies and admits it.
- On connect the two exchange roster heads and missing operations, then peer
  lists (members' current rendezvous keys), then log heads (*Logs*) and
  content inventories (*Swarming*).

## Content

A blob (a video, an image, any file) is:

1. **Encrypted** with a random per-blob key under XChaCha20-Poly1305 in
   fixed-size **pieces** (default 256 KiB; each piece's nonce is its index),
   so any piece can be decrypted alone and a stream can start anywhere.
2. **Addressed** by a BLAKE3 tree over the ciphertext pieces: the blob ID is
   the root, and every piece verifies against it with a short proof, so a
   peer can serve and a fetcher can check any piece without the rest.
3. **Announced** by its author as an entry in its log (*Logs*): blob ID,
   size, the per-blob key wrapped under the current `epochKey`, and app
   metadata (title, thumbnail, MIME type), all encrypted.

Because the blob ID is a hash of ciphertext under a random key, someone who
holds the same plaintext can't compute it, and the same file shared twice
gets two IDs.

## Logs

Each member has an append-only **log** in each group: entries signed by its
member key, numbered, each naming the hash of the one before, so a log can't
be forked or rewritten without detection. Entries are encrypted under the
epoch key current when written. Two kinds:

- **blob announcements** (*Content*), which the library acts on;
- **app entries**: opaque bytes (a chat message, a comment, a reaction)
  that the library stores, replicates and hands to the app in order.

Members replicate each other's logs over sessions: on connect each sends the
latest sequence number it holds of every log, and the other sends what's
missing. Any member can serve another's log, so a member offline for a
week catches up from whoever is around.

**Removal and logs.** A removed member's log keeps the entries it wrote
before removal. The `remove` operation records the highest sequence number
of that log the removing admin had seen, and members accept nothing past
it. Without a trusted clock an entry written offline just before removal
can't be told from one backdated after, so this cut is the rule: a removed
member's late offline writes are dropped rather than its forgeries kept.

## Swarming

A fetcher asks every connected member for the pieces of a blob they hold
(a bitfield, then updates as pieces arrive) and schedules:

- **rarest first**, from the bitfields, so pieces spread fast;
- **in order near the playhead** when streaming, so playback can start
  after the first few pieces;
- **pipelined** requests per peer, sized to its measured throughput, and
  **work stealing** at the end so one slow peer doesn't hold the last piece;
- every piece verified against the tree before it is kept or served on.

Any member holding pieces serves them by default, so a fetch draws on the
whole group's upload; the app can turn serving off or cap its rate per
device (a phone on cellular, say). A device keeps what it fetched up to a
storage budget the app sets, evicting the least recently used. A partial download resumes from the
pieces on disk.

**Blind mirrors** (an always-on device that serves without reading) are
added with a `mirror` flag: they receive `G` (to find the directory) but no
epoch keys, so they fetch and serve ciphertext and verify pieces by the tree
but can't unwrap blob keys or read logs. A rekey seals the new `G'` to
mirrors as to members, and the new epoch key to members only.

## Removal

Removing a member:

1. An admin writes `remove`, then a `rekey`: a fresh group secret `G'`
   sealed to every remaining member and mirror, and a fresh epoch key sealed
   to every remaining member, each to its X25519 key (derived from its
   member key).
2. Members apply it as they receive it: they move to `G'`'s directory and
   wrap new blob keys under the new epoch key. A member that, after applying
   the rekey, sees an `add` concurrent with it (a new member the rekeying
   admin didn't know of) seals `G'` and the new epoch key to that member in
   a follow-up operation, so nobody added around a rekey is left behind.
3. The removed member keeps what it already had (blobs and log entries from
   before its removal) but can't unwrap anything announced after, can't find
   the new directory, and is refused by every member that has applied the
   removal.

A rekey **invalidates outstanding invites**: they carry the old `G`, whose
directory members stop using. Admins reissue invites after removing someone.

This costs one sealed copy per member per removal, fine for v1 group sizes;
a tree scheme (MLS/TreeKEM) can replace it for large groups.

## Invites

An invite is `G`, the inviting admin's member key, the shard count, and a few
bootstrap hints (current rendezvous keys of members likely online, DHT
contacts in the right community), encoded as a link or QR code. The holder
finds the group's directory and sends a join request in its first session;
it is admitted only when an admin writes an `add`, which delivers the
current `G` and the epoch keys sealed to it. Single-use or expiring invites
carry a token signed by the admin and are refused after use or expiry. A
rekey invalidates every outstanding invite (*Removal*).

An invite reveals `G`, so a leaked invite lets the holder read the
directory (rendezvous keys, not member keys or addresses) and disrupt it
(*Discovery*) until the next rekey, but not join (no admin `add`) and not
read content (epoch keys are never derivable from `G`).

## Library surface

```go
g, err := group.Create(ep, store, group.Policy{Name: "family"})
g, err := group.Join(ctx, ep, store, invite)

invite, err := g.Invite(group.InviteOptions{Uses: 1, Expires: 24 * time.Hour})
err = g.Add(ctx, memberKey, "Alice", group.RoleMember) // admin only
err = g.Remove(ctx, memberKey)                         // admin only, rekeys

id, err := g.Publish(ctx, file, meta)  // a blob, announced in our log; meta encrypted
r, err := g.Open(ctx, id)              // io.ReadSeeker; fetches as read
err = g.Fetch(ctx, id)                 // fetch fully in the background
err = g.Post(ctx, entry)               // an app entry in our log (chat, comment)
entries, err := g.Log(member, from)    // a member's log entries from a sequence number
g.SetServing(group.Serving{Enabled: true, MaxRate: 500 << 10})

for ev := range g.Events() { ... }     // member joined/left, entry or blob arrived, progress
```

`store` is an interface (filesystem by default) for pieces, roster and keys,
so an app chooses where data lives and how much.

## Scale and cost

- **v1 target:** groups of up to about 50 members (decided). Rekey is one
  sealed copy per member; the directory three shards.
- **Idle cost** for a member: a directory read and write every half hour,
  plus warren's listening keepalives.
- **Memory:** sessions use hysteria2's capped windows; a fetch holds a
  bounded window of pieces in memory; the roster is small.

## Warren changes needed

1. **Several listeners per endpoint** (one per group, each on its own
   socket), and `Authorize` given the listener key that was called.
2. **Mutable-item CAS writes** from the endpoint, for the directory (the
   DHT supports CAS; the endpoint doesn't expose puts yet).
3. Nothing in the data plane: sessions are hysteria2 over `Conn`.

## Phasing

1. Keys, identity, roster (folding, gossip), logs, invites. Unit-tested.
2. Warren: multiple listeners, listener-aware `Authorize`; directory over
   mutable items. Discovery and sessions between members in the simulator.
3. Content: encryption, tree, announcements; single-source fetch.
4. Swarming: bitfields, rarest-first, streaming order, work stealing,
   resume, storage budget.
5. Removal and rekey; blind mirrors.

## Decisions

1. **Group size:** up to about 50 members in v1, so pairwise rekey and three
   directory shards. A tree scheme (MLS/TreeKEM) is the path past
   that.
2. **Roles:** admin (add, remove, rekey) and member (post, fetch).
3. **Serving:** every member serves what it holds by default; the app can
   turn serving off or cap it per device.
4. **Logs:** the library includes a signed per-member log. Blob
   announcements and app entries (chat, comments) go through it, so apps
   like Murmur get feeds without building their own.
