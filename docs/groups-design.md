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
member (members see each other's addresses when they connect),
deniability, and hiding from a DHT node that the same IP address is behind
two groups (see *Identity*).

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

A group has a random 32-byte **group secret** `G`, made by the founder and
delivered only to members, sealed in the `add` that admits each (*Roster*).
Invites don't carry it (*Invites*). Keys derived from `G` with HKDF-SHA256
(labels abbreviated):

| Key | Derivation | Use |
|---|---|---|
| `dirKey` | `HKDF(G, "warren/group/v1 directory")` | each period's directory signing key and salts (*Discovery*) |
| `dirSeal` | `HKDF(G, "… directory seal")` | encrypts directory shards |
| `blind[p]` | `HKDF(G, "… blind" ‖ p)` | blinds member keys into period `p`'s rendezvous keys (*Identity*) |

**Epoch keys** wrap content keys (*Content*, *Logs*). `epochKey[0]` is random,
made by the founder; each later one is made on a rekey (*Removal*). Epoch
keys travel only sealed to individual members (in `add`, `rekey` and
`deliver` operations), so a blind mirror, which gets `G` but no epoch keys,
can't read content.

**Periods** are one hour. Everything visible on the DHT (the directory's
signing key and salts, members' rendezvous keys) derives from the period, so
nothing there repeats across hours.

A rekey (*Removal*) replaces both `G` and the epoch key.

## Identity

Each device holds a separate ed25519 **member key** per group, generated on
join and never reused across groups. It signs the device's roster and log
operations, and peers check it inside every session. It never appears on
the DHT.

On the DHT the device is reached under a **rendezvous key**: its member key
blinded for the period, as Tor v3 blinds onion service keys. The blinded
public key is the member public key times a scalar derived from `blind[p]`,
and the matching private key is the member's private scalar times the same
factor, so:

- any member can compute any other member's rendezvous key for any period
  from the roster, without asking anyone;
- only the member itself can sign as it, so only it can listen under it;
- without `G`, a rendezvous key is unlinkable to the member key or to the
  same member's key in another hour.

The device listens under its current rendezvous key with `endpoint.Listen`.
Warren's signaling records are signed by the listener key and stored by
holders next to the listener's address, so a holder sees a key that changes
every hour and means nothing without `G`.

A device in several groups listens under one rendezvous key per group, each
on its own socket. That hides the link from holders only where a shared NAT
or carrier-grade NAT puts many devices behind one address. On a public
address, a holder of two of the device's records sees one IP behind both and
can link the memberships. That is a stated non-goal for v1 (*Goals*);
routing each group's listening through different relays could close it
later.

## Roster

The roster is a set of operations signed by member keys, kept by members
(not on the DHT) and exchanged over sessions:

- `genesis` (founder key, group name, shard count, and `G` and
  `epochKey[0]` sealed to the founder);
- `add` (member key, display name, role or `mirror`, and the current `G`
  and every epoch key so far sealed to the new member; a mirror gets `G`
  only) by an admin;
- `remove` (member key, and the highest sequence number of its log the
  remover has seen, see *Logs*) by an admin;
- `rekey` (see *Removal*) by an admin;
- `invite` (an invite's public key and expiry, see *Invites*) by an admin;
- `deliver` (the current `G` and epoch key sealed to one member already
  added) by any member: it grants no rights, so it isn't admin-checked, and
  only fills in keys a member missed (*Removal*).

Operations carry a Lamport clock and their causal parents (the hashes of the
latest operations the author had seen). Folding is deterministic:

- operations apply in causal order; each is checked **when applied**, and
  counts only if its author is an admin at that point;
- **remove wins** over a concurrent `add` of the same key;
- concurrent removals between admins all apply, unless that would leave no
  admin: then the removal by the **more senior** admin (added earlier in
  the fold) stands. Seniority is fixed by history, unlike a hash an author
  could grind;
- once a member has applied an author's removal, it rejects every operation
  from that author it receives afterwards, whatever parents or clock it
  claims, so a removed admin can't backdate operations into the past.

Members exchange operations they lack at the start of every session
(*Sessions*), so the roster converges by gossip.

Roles in v1: `admin` (add, remove, rekey), `member` (post, fetch) and
`mirror` (store and serve ciphertext only).

## Discovery

Members don't need the DHT to find each other's keys: rendezvous keys are
computed from the roster (*Identity*). What a member needs on a cold start,
after a long absence, is to know **who is online**, so it doesn't spend
signaling lookups on members who aren't. The **directory** is that liveness
hint.

The directory is a set of BEP 44 mutable items, one per shard, rotated each
period:

- signing key: `seed = HKDF(dirKey, "directory key" ‖ p)`, so the `k` every
  put and reply carries changes every hour;
- salt: `HMAC(dirKey, "directory salt" ‖ p ‖ shard)`;
- value, sealed under `dirSeal`: entries of a 32-byte rendezvous key and a
  4-byte last-seen time, about 25 in the 1,000-byte BEP 44 limit after the
  seal's overhead. A reader keeps only entries whose rendezvous key matches
  a roster member's key for that period, so no signature is needed.

The genesis sets the shard count from the expected size, at most 20 members
per shard to leave headroom: three shards for a group of 50. A member hashes
to one shard; when a shard is full, its oldest entries are dropped.

**Cost and exposure.** A member reads the directory only on a cold start,
when it has no session to any member, and writes its own entry once a
period, through one connected member that does the period's puts for the
members it's in session with (so the nodes storing a shard see one address a
period, not every member's). A device with no session yet does its own
reads and writes. The nodes storing a shard still learn that some addresses
use one opaque target in an hour; members who must hide even that should
route directory traffic through relay routers (a later option).

**BEP 44 compare-and-swap isn't atomic across storing nodes,** so two members
writing a shard at once can each win on some replicas. A writer re-reads
after its put and re-merges if its entry is missing; readers merge what
they find across replicas; and sessions gossip liveness anyway.

## Sessions

A session is a hysteria2 connection between two members over a punched
path (`endpoint.Connect`, `transport/hy2`), so it inherits migration, stall
recovery and memory caps.

- **Admission before anything is served.** A member's listener admits a
  caller whose key is a roster member's rendezvous key for the current,
  previous or next period (computable from the roster; the neighbors cover a
  call across a period boundary). Then, inside the encrypted session, each
  side signs the session's secret with its **member key**, and each checks
  the other's member key is on its roster. Nothing is served before both
  checks pass. Warren needs two changes for this: an endpoint listening under
  several keys at once (today the DHT node holds a single listener), and
  `Authorize` told which listener key was called.
- **A newer roster than the callee's** (a member added since the callee last
  synced): the caller presents the signed `add` chain first; the callee
  verifies and admits it.
- On connect the two exchange roster heads and missing operations, then
  liveness (members each has reached lately), then log heads (*Logs*) and
  content inventories (*Swarming*).
- **Join sessions** (*Invites*) are separate: they are admitted under an
  invite's key, carry only a join request and its answer, and serve no
  member data.

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
head of every log it holds (sequence number and entry hash), and the other
sends what's missing. Two different entries at the same sequence number,
both signed by the author, are proof the author forked its log: members keep
the proof, stop accepting that log, and tell the app. Any member can serve
another's log, so a member offline for a week catches up from whoever is
around.

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
2. A member that learns of a `remove` applies it, and any rekey, **before it
   publishes anything**, so it wraps new blob keys under the new epoch key
   and moves to `G'`.
3. **Concurrent changes.** If, after folding, the current rekey turns out to
   have sealed keys to a member the fold removed (two admins removing two
   members at once), it is superseded: an admin issues a fresh rekey sealed
   only to the members the fold keeps. A member added concurrently with a
   rekey (one the rekeying admin didn't know of) gets `G'` and the new epoch
   key from any member that notices, in a `deliver` operation.
4. **Members offline during a rekey.** For seven days after a rekey, the
   remaining members also listen under their rendezvous keys from the old
   `G`. A member that missed the rekey reaches them there, and gets the
   rekey by roster gossip. The removed member can compute those keys too,
   but every member that applied the removal refuses it.

What the removed member keeps: everything from before its removal. What it
loses: anything published under the new epoch key, the new directory, and
every session. The guarantee holds for content published by members who
have applied the removal: a member that hasn't heard of it yet still
publishes under the old epoch key, which the removed member holds, until it
does. Step 2 keeps that window as short as gossip.

This costs one sealed copy per member per removal, fine for v1 group sizes;
a tree scheme (MLS/TreeKEM) can replace it for large groups.

## Invites

An invite is a random **invite secret** `I`, an expiry, a token signed by
the inviting admin, the group's display name, and a few bootstrap hints
(DHT contacts in the right community), encoded as a link or QR code. It
carries neither `G` nor any member key.

- The admin records the invite in the roster as an `invite` operation
  (the invite's public key and expiry), so other online members can admit
  its join session too.
- While the invite is valid, the admin (and any member that wants to help)
  listens under a per-period rendezvous key derived from `I`. The invitee
  derives the same key and calls it with its own key, also derived from `I`.
- That **join session** carries the invitee's new member key, display name
  and the signed token, and nothing else. An admin approves with an `add`,
  which delivers `G` and the epoch keys sealed to the new member, and the
  invitee leaves the join session for normal ones.
- Single-use invites are spent at the first `add` against them; all are
  refused after expiry or after a rekey (*Removal*).

A leaked invite lets its holder ask to join, nothing more: it can't read the
directory or content, find members, or join without an admin's `add`.

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
  sealed copy per member; the directory three shards of at most 20.
- **Idle cost** for a member: a directory read and write every half hour,
  plus warren's listening keepalives.
- **Memory:** sessions use hysteria2's capped windows; a fetch holds a
  bounded window of pieces in memory; the roster is small.

## Warren changes needed

1. **Several listeners per endpoint** (one per group, each on its own
   socket, plus invite listeners), and `Authorize` given the listener key
   that was called.
2. **Ed25519 key blinding** for rendezvous keys (scalar multiplication on
   the curve, as in Tor's rend-spec-v3).
3. **Mutable-item puts** from the endpoint, for the directory (the DHT
   supports them; the endpoint doesn't expose puts yet).
4. Nothing in the data plane: sessions are hysteria2 over `Conn`.

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
