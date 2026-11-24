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
  group exists, who is in it, or what it shares, or link a member's
  identifiers across groups or across time. The DHT sees only rotating,
  keyed, opaque targets and encrypted values.
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
two groups, or behind one rendezvous key after another across periods (see
*Identity*): rotating identifiers don't hide a stable address.

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
| Topic a plain hash of the PSK | HKDF-derived keys; per-period directory keys and blinded member keys (*Keys*, *Identity*) |

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
keys travel only sealed to individual members (in `genesis`, `add`,
`remove`, `rekey` and `deliver` operations), so a blind mirror, which gets `G` but no epoch keys,
can't read content. Each epoch key is named by the hash of the operation
that made it, and every encrypted entry names the epoch key it used, so a
member keeps every epoch key sealed to it and can read content written under
any of them.

Every operation that makes keys (`genesis`, `remove`, `rekey`) also carries
a **commitment** to them: a hash of the new `G` and of the new epoch key,
under a fixed label. A member checks any key it is given, whoever seals it,
against the commitment of the operation that made it.

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
- `add` (member key, display name, role, and the current `G` and every
  epoch key so far sealed to the new member; a mirror gets `G` only) by an
  admin, or by the owner when the role is `admin`. A role is fixed when the
  key is added: v1 has no role changes, and an `add` of a key already on
  the roster never counts, with one exception: two concurrent `add`s of the
  same key have both sealed their keys, so the key takes the role holding
  more (admin over member over mirror) rather than leaving a mirror with
  epoch keys. To change a device's role, it is removed and
  added again under a fresh member key (a full removal, see *Open
  problems*);
- `remove` (member key; the remover's view of that member: the hashes of its
  latest roster operations and the head of its log the remover has seen,
  sequence number and entry hash; and the rekey, see *Removal*) by an admin,
  or by the owner when the removed key is an admin, as one operation;
- `rekey` (a fresh `G` and epoch key on their own, see *Removal*) by an
  admin;
- `invite` (an invite's public key and expiry, see *Invites*) by an admin;
- `deliver` (the current `G`, and for a member but not a mirror any epoch
  keys it lacks, sealed to one member already added) by any member: it
  grants no rights, and only fills in keys a member missed (*Removal*). The
  recipient checks each key against the commitment of the operation that
  made it (*Keys*), so a forged key is ignored. A sender delivers only to
  a recipient on its own folded roster, which a counting `remove` takes it
  off, and withholds nothing else: withholding after a `remove` that doesn't
  count would starve a member still on the roster.
  A `deliver` to a recipient removed concurrently doesn't count but has
  still handed over its keys, so it is treated like a key sealed to a
  removed member (*Removal*, step 3). One whose author was removed
  concurrently leaks nothing: the author already held those keys.

Every operation names the genesis's hash, which is the group's ID, and
carries a Lamport clock and its causal parents (the hashes of the latest
operations the author had seen). Folding is deterministic:

- operations apply in one **total order** every member computes alike: a
  topological order of the causal graph that, among operations whose
  parents are all placed, takes the lowest Lamport clock and then the lowest
  hash first. (Sorting by Lamport clock alone would break causal order
  whenever an author writes a clock lower than a parent's.)
- `genesis` is valid only as the root: no parents, signed by the founder key
  it names, and it makes the founder the group's **owner**;
- each other operation is checked **when applied**, against the roster the
  fold has built up to that point: `add`, `remove`, `rekey` and `invite`
  count only if the author is an admin or the owner then, and adding or
  removing an admin only if the author is the owner; a `remove` of the
  owner key never counts, whoever signs it; `deliver` counts only if its
  author and recipient are members then. An operation whose author's
  own `add` didn't count therefore never counts;
- the **current keys** are those made by the last key-making operation that
  counts in the total order. Two concurrent rekeys by different admins
  therefore resolve the same way on every member, and the losing rekey's
  epoch key stays readable (*Keys*);
- **a removed key never returns**: an `add` of a key that a counting
  `remove` earlier in the total order removed doesn't count, and a `remove` of a key that is no longer on the roster
  when applied doesn't count either (members keep any keys it sealed to
  them, so content written under them stays readable);
- operations by a removed author count only if the `remove` names them, or
  their descendants, in its view of that author. That depends only on the
  `remove`'s content, not on when anything arrives, so every member folds
  the same roster, and a removed admin can't backdate operations into the
  past. A legitimate operation by that author the remover hadn't seen yet is
  dropped too: the price of a rule everyone applies alike.

**Why one owner.** Only the owner changes who is an admin, and the owner is
never removed, so no two operations can remove each other's authors. Without
a trusted clock, every rule for admins removing each other at once lets a
compromised admin either strike back at its remover, make itself
unremovable, or grant itself authority through an admin it adds; a single
owner rules that out. The owner's operations fold like any others; its
authority is absolute, so its operations can't conflict with each other's
authority. v1 can't detect a stolen owner key: the app shows every roster
change as an event, so people can notice and recreate the group. The cost: a lost or compromised owner key
can't be replaced in v1. The group keeps working but its admins are fixed,
and if the owner key is compromised, the members recreate the group.

Members exchange operations they lack at the start of every session
(*Sessions*), so the roster converges by gossip.

Roles in v1: the `owner` (the founder: everything an admin does, plus
adding and removing admins), `admin` (add and remove members and mirrors,
rekey, invite), `member` (post, fetch) and `mirror` (store and serve
ciphertext only).

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
after its put and re-merges if its entry is missing; readers merge every
distinct value they find across replicas (which needs a warren change, see
*Warren changes needed*); and sessions gossip liveness anyway.

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
- **A caller the callee doesn't know yet** (a member added since the
  callee last synced): signaling can't carry the proof, since admission
  comes before any session. The callee admits a caller whose key it doesn't
  recognize only if the caller's key is the **sync key** for the call:
  an ed25519 key whose seed is `HKDF(G, "sync" ‖ p ‖ callee's rendezvous
  key)`. Signaling offers are signed by the caller key, so the key itself is
  the proof that the caller holds `G`, and it reaches the callee before any
  session exists. A DHT holder sees the callee's rendezvous key in its
  record but can't compute the sync key. The callee admits such a caller
  into a **sync session** that serves nothing until the caller presents a
  signed `add` chain admitting a member key, and signs the session's secret
  with that key. This opens the callee to members and recently removed
  members (who hold `G` during the grace window, see *Removal*, and are
  refused once the chain is checked), and nobody else.
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
around (unless a rekey happened meanwhile, see *Removal*).

**Removal and logs.** A removed member's log keeps the entries it wrote
before removal. The `remove` operation records the head of that log the
removing admin had seen (sequence number and entry hash), and members accept
only entries on the chain ending at that head: nothing past it, and nothing
below it that the head's hash chain doesn't lead to, so the removed member
can't sign a different history below the cutoff. Only the removal that
counts sets the cutoff: if two admins remove the same member concurrently,
the one first in the total order counts and the other doesn't (*Roster*),
so entries only the second remover had seen are dropped too. Entries a member had
already accepted past the final cutoff are withdrawn, and the app told.
Without a trusted clock an entry written offline just before removal
can't be told from one backdated after, so this cut is the rule: a removed
member's late offline writes are dropped rather than its forgeries kept.

## Swarming

Each session exchanges **inventories**: the blob ID, size and piece size of
every blob a side holds, readable without epoch keys. That is how a fetcher
learns who has a blob, and how a blind mirror learns what to fetch.

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
added with the `mirror` role: they receive `G` (to find the directory) but no
epoch keys, so they fetch and serve ciphertext and verify pieces by the tree
but can't unwrap blob keys or read logs. One exception, from concurrency:
an admin that hasn't yet seen a change can seal an epoch key to a device the
fold ends up treating as a mirror; the corrective rekey (*Removal*) keeps
that from reaching the current key, but the earlier one stays readable to
it. A mirror fetches every blob in the
inventories it receives, up to its storage budget; it learns blob IDs and
sizes, which it would see by serving anyway. A rekey seals the new `G'` to
mirrors as to members, and the new epoch key to members only.

## Removal

Removing a member:

1. An admin writes `remove`, which carries the rekey in the same operation: a
   fresh group secret `G'` sealed to every remaining member and mirror, and a
   fresh epoch key sealed to every remaining member, each to its X25519 key
   (derived from its member key). One operation, so no member can apply the
   removal without the new keys.
2. A member that learns of a `remove` applies it **before it publishes
   anything**, so it wraps new blob keys under the new epoch key and moves to
   `G'`. Applying it also closes every session with the removed member's
   key, abandoning requests in flight, since admission was checked only when
   those sessions opened.
3. **Concurrent changes.** If, after folding, the current keys turn out to
   have been sealed or delivered to a member the fold removed (two admins
   removing two members at once, or a `deliver` to a member being removed),
   they are superseded: an admin issues a `rekey` sealed
   only to the members the fold keeps. Until that `rekey` arrives, a member
   **publishes nothing**: the app's posts and blobs wait in a queue. Anything
   published before a member learned of the concurrent removal was readable
   by the removed member; that window is as short as gossip and can't be
   closed. The condition also covers the other ways honest concurrency puts
   the current keys where they don't belong (on a key whose `add` didn't
   count, or on a mirror): each comes from a key-maker that hadn't seen a
   removal, which therefore also sealed them to the removed member. The
   roster model checks this (*Open problems*). A member added concurrently with any key-making operation (a `remove`
   or a `rekey` whose author didn't know of the `add`) gets the new `G` and
   any epoch keys it lacks from any member that notices, in a `deliver`
   operation.
4. **Members offline during a key change.** For 24 hours after any
   operation that replaces `G` (a `remove` or a `rekey`, including a
   corrective one), the remaining members also listen under their
   rendezvous keys from each `G` superseded in that window. A member that
   missed the change reaches them there, and gets it by roster gossip. A
   member offline longer is out until an admin removes its old key and
   re-invites it under a new one (the owner does both if it was an admin;
   see *Invites*): it holds only secrets the removed member also holds, so
   nothing else can tell them apart.

What the removed member keeps: everything from before its removal. What it
loses: anything published under the new epoch key, the new directory, and
every session. Two limits, both inherent to members going offline:

- a member that hasn't heard of the removal yet still publishes under the old
  epoch key, which the removed member holds, until it does (step 2 keeps
  that window as short as gossip);
- during the 24-hour window, the removed member can compute members' old
  rendezvous keys and see from signaling records who is online, though every
  member refuses its sessions.

This costs one sealed copy per member per removal, fine for v1 group sizes;
a tree scheme (MLS/TreeKEM) can replace it for large groups.

## Invites

The inviting admin makes an ed25519 **invite key** and keeps its private
half. An invite carries the invite **public** key, a random **invite
secret** `I`, an expiry, the group's display name, and a few bootstrap hints
(DHT contacts in the right community), encoded as a link or QR code. It
carries neither `G` nor any member key.

- The admin records the invite in the roster as an `invite` operation (the
  invite public key and expiry).
- While the invite is valid, the admin listens under the invite key blinded
  per period, as in *Identity* but with the factor derived from
  `HKDF(I, "invite blind" ‖ p)` instead of from `G`. The invitee computes
  that key from the invite's public half and `I`, and calls it with a fresh
  key of its own. Without `I`, the blinded key can't be linked to the invite
  key. Only the admin holds
  the invite's private key, so only the admin can listen there, and one
  listener means no clash at holders.
- That **join session** carries the invitee's new member key, display name,
  and a proof that it knows `I` (a MAC over the session's secret), and
  nothing else. The admin approves with an `add`, which delivers `G` and the
  epoch keys sealed to the new member. The join answer also carries the
  genesis and the roster's operations (small for v1 groups), so the invitee
  can check its own `add` and compute the members' rendezvous keys. The
  invitee then leaves the join session for normal ones.
- Single-use invites are spent at the first `add` against them; all are
  refused after expiry, and invites issued before a removal are refused
  after it (*Removal*). An admin re-invites a
  member that was offline through a removal the same way: it removes the
  old key first, then issues the invite; for a former admin, the owner does
  both.

A leaked invite lets its holder ask to join, nothing more: it can't
impersonate the admin, read the directory or content, find members, or
join without an admin's `add`.

## Device restore

A device restored from a backup must not sign anything until it has fetched
its own latest roster operations and log head from members; otherwise it
reuses sequence numbers, which members take as proof its log forked. A
device that can't reach a member waits (and the app is told) rather than
signing.

## Open problems

The fold, the authority rules, key delivery and the corrective rekey are
model-checked by `group/rostermodel`: an abstract model of this section's
rules (keys as names, sealing as recipient sets) and an explorer that runs
every interleaving of an owner, two admins and a member writing, syncing,
and acting as compromised or removed authors (5.1 million states at depth
6, about six minutes; `go test` runs depth 4 in seconds). It checks that the owner keeps its role, only the owner makes admins,
backdated operations by removed authors never count, the view rule settles
(in at most three passes), and once the corrective rekey and deliveries run,
no off-roster key holds the current group secret or epoch key, mirrors hold
the current group secret but no current epoch key, and every member holds
the current keys and every epoch key any other member holds. Admins and
members also sign, as compromised devices would, the operations their role
has no authority for, and none may count. (No explored replica is a mirror,
so mirrors' authority, the same rule as members', isn't explored.) Mutation tests break each authority rule,
the view rule, delivery's roster check and the corrective rekey in turn, and
the explorer catches each. It found
two rules above that were wrong as first written (concurrent duplicate
`add`s, and `deliver` withholding after any `remove`), and writing it pinned
the total order down as an algorithm.

Still open, and not modeled (the grace window, invites and log cutoffs are
outside the model):

- **Re-invites and role changes are full removals.** Each rekeys the group,
  cuts the device's log at the remover's view (dropping what it wrote
  offline), refuses earlier invites, and starts a new 24-hour window that
  can push other long-offline members out in turn. A lighter **replace key**
  operation, with no rekey, for a device that holds only secrets the group
  already gave it, is the likely fix.
- **Owner compromise** is detectable only by people watching roster events.
- **An owner offline past the grace window** can't come back the way other
  members do, since its key can't be removed and re-invited. It needs a
  path that keeps its authority: for example, a join-style session it opens
  under its own key, through which an admin delivers the current keys.
- **Concurrent removals of the same member** keep only the first remover's
  log cutoff, dropping entries only the second had seen.

## Library surface

```go
g, err := group.Create(ep, store, group.Policy{Name: "family"})
g, err := group.Join(ctx, ep, store, invite)

invite, err := g.Invite(group.InviteOptions{Uses: 1, Expires: 24 * time.Hour})
err = g.Add(ctx, memberKey, "Alice", group.RoleMember) // admin only; owner only for RoleAdmin
err = g.Remove(ctx, memberKey)                         // admin only; owner only for an admin; rekeys

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
- **Idle cost** for a member: one directory write a period, often made for
  it by a member it's in session with; directory reads only on a cold start;
  plus warren's listening keepalives.
- **Memory:** sessions use hysteria2's capped windows; a fetch holds a
  bounded window of pieces in memory; the roster is small.

## Warren changes needed

1. **Several listeners per endpoint** (one per group, each on its own
   socket, plus invite listeners), and `Authorize` given the listener key
   that was called.
2. **Ed25519 key blinding** for rendezvous keys (scalar multiplication on
   the curve, as in Tor's rend-spec-v3). A blinded key is a bare scalar, not
   an `ed25519.PrivateKey`, so every API that takes or keeps a signing key
   moves to a signer interface that can sign with one: listening
   (`endpoint.Listen`, `driver.Node.Listen`, `dht.Node.Listen`/`ListenKey`),
   calling (`endpoint.Connect`, `driver.Node.Signal`, `dht.Node.Signal`),
   and the identity a `Conn` keeps to sign migration and resume offers.
3. **Mutable-item puts** from the endpoint, for the directory (the DHT
   supports them; the endpoint doesn't expose puts yet), and **reads that
   return every distinct value** the replicas hold, including different
   values at the same sequence number. Today a get keeps one value per
   sequence number and `driver.Node.GetMutable` returns only the newest, so
   the directory merge (*Discovery*) would miss concurrent writes.
4. Nothing in the data plane: sessions are hysteria2 over `Conn`.

## Phasing

1. Keys, identity, roster (folding, gossip), logs. Unit-tested.
2. Warren: multiple listeners, a signer interface, listener-aware
   `Authorize`; directory over mutable items. Discovery, sessions and
   invites between members in the simulator.
3. Content: encryption, tree, announcements; single-source fetch.
4. Swarming: bitfields, rarest-first, streaming order, work stealing,
   resume, storage budget.
5. Removal and rekey; blind mirrors.

## Decisions

1. **Group size:** up to about 50 members in v1, so pairwise rekey and three
   directory shards. A tree scheme (MLS/TreeKEM) is the path past
   that.
2. **Roles:** owner (the founder, who alone adds and removes admins), admin
   (add and remove members, rekey, invite), member (post, fetch), and mirror
   (stores and serves ciphertext only).
3. **Serving:** every member serves what it holds by default; the app can
   turn serving off or cap it per device.
4. **Logs:** the library includes a signed per-member log. Blob
   announcements and app entries (chat, comments) go through it, so apps
   like Murmur get feeds without building their own.
