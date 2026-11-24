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

A group is created from a random 32-byte **group secret** `G`. Everything
else derives from it with HKDF-SHA256 (label in quotes):

| Key | Derivation | Use |
|---|---|---|
| `dirKey` | `HKDF(G, "warren/group/v1 directory")` | locates and signs the group directory (*Discovery*) |
| `dirSeal` | `HKDF(G, "… directory seal")` | encrypts directory entries |
| `rosterKey` | `HKDF(G, "… roster")` | encrypts roster operations |
| `epochKey[n]` | delivered on each rekey (*Removal*); `epochKey[0] = HKDF(G, "… epoch 0")` | wraps content keys |

Topics are `HMAC(dirKey, "topic" ‖ period)` with a one-hour `period`, so a
target says nothing without `G` and doesn't repeat across hours.

**Removal changes `G` too** (*Removal*): a removed member knows the old `G`,
so it could still find the directory and see which keys appear in it. After
a rekey the remaining members move to `G' ` and the old directory goes
quiet.

## Identity

Each device holds a separate ed25519 **member key** per group, generated on
join and never reused across groups, so two groups' rosters never share a
key. The member key is what the device listens under on warren
(`endpoint.Listen`), what signs its roster operations and content
announcements, and what peers pin when they connect.

## Roster

The roster is a set of signed operations, each encrypted under `rosterKey`
and stored by members (not on the DHT):

- `genesis` (founder key, group name, policy);
- `add` (member key, display name, role) signed by an admin;
- `remove` (member key) signed by an admin;
- `rekey` (epoch n, see *Removal*).

Operations carry a Lamport clock and their causal parents (the hashes of the
latest operations the author had seen). Folding is deterministic: replay in
causal order, breaking ties by hash; an operation counts only if its author
was an admin at that point; **remove wins** over a concurrent add of the
same key. Members exchange roster operations they lack at the start of
every session (*Sessions*), so the roster converges by gossip.

Roles in v1: `admin` (can add, remove, rekey) and `member`. The founder is
the first admin and can be removed like any other once another admin
exists.

## Discovery

Members find each other's **member keys** through the group directory, then
reach each other with warren's existing Connect-by-key (encrypted signaling,
holders, relays, NAT punching). No member's address is ever published
under a group topic.

The **directory** is a set of BEP 44 mutable items under the current
period's topic, signed by an ed25519 key derived from `dirKey` (so any
member can write, nobody else can forge), salted by shard:

- `target = MutableTarget(dirPub, HMAC(dirKey, period ‖ shard))`;
- value: sealed under `dirSeal`, up to ~900 bytes: member keys seen alive
  recently, with a last-seen time, about 20 per shard.

A member that comes online reads the current and previous period's shards,
merges, adds itself, and puts back the shard its key hashes to (with CAS on
the sequence number, retrying on conflict). It repeats every half period.
Members it finds it calls with `endpoint.Connect`; once one session is up,
roster and peer lists flow over sessions, so the directory matters mostly
for a cold start or after a long absence.

Small groups need one shard; the shard count is in the genesis.

## Sessions

A session is a hysteria2 connection between two members over a punched
path (`endpoint.Connect`, `transport/hy2`), so it inherits migration, stall
recovery and memory caps.

- **Authorization before anything is served.** The callee accepts a caller
  only if the caller's key is on its current roster for the group it was
  called on. Warren needs two changes for this: an endpoint listening under
  several keys at once (one per group; today the DHT node holds a single
  listener), and `Authorize` told which listener key was called, not just
  the caller's.
- **A newer roster than the callee's** (a member added since the callee last
  synced): the caller may present the signed `add` chain in its first
  message; the callee verifies and admits it.
- On connect the two exchange roster heads and send each other missing
  operations, then peer lists (members recently reached, with nothing
  addressable), then content inventories (*Swarming*).

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
week catches up from whoever is around. Removal (*Removal*) doesn't rewrite
logs: entries a removed member wrote before removal stay, and members
ignore entries it writes after.

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
device (a phone on cellular, say). A device keeps what it fetched up to a storage budget the app sets,
evicting the least recently used. A partial download resumes from the
pieces on disk.

**Blind mirrors** (an always-on member that serves without reading) are a
member with storage but without epoch keys: it fetches and serves
ciphertext and verifies pieces by the tree, but can't unwrap blob keys.

## Removal

Removing a member:

1. An admin writes `remove`, then a `rekey`: a fresh group secret `G'` and
   epoch key, each sealed to every remaining member's X25519 key (derived
   from its member key), in the operation.
2. Members apply it as they receive it: they move to `G'`'s directory and
   wrap new blob keys under the new epoch key.
3. The removed member keeps what it already had (blobs announced before its
   removal) but can't unwrap anything announced after, can't find the new
   directory, and is refused by every member that has applied the removal.

This costs one sealed copy per member per removal, fine for v1 group sizes;
a tree scheme (MLS/TreeKEM) can replace it for large groups.

## Invites

An invite is `G`, the inviting admin's key, the group's shard count, and a
few bootstrap hints (member keys likely online, DHT contacts in the right
community), encoded as a link or QR code. Anyone holding it can find the
group and ask to join; they're admitted only once an admin adds their member
key. The joiner's first session carries a join request; an admin approves
it with an `add`. Single-use or expiring invites sign a token with the
admin's key and are refused after use or expiry.

An invite reveals `G`, so a leaked invite lets the holder see the directory
until the next rekey, but not join (no admin `add`) and not read content
(epoch keys are delivered only to members).

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
  sealed copy per member; the directory one shard.
- **Idle cost** for a member: a directory read and write every half hour,
  plus warren's listening keepalives.
- **Memory:** sessions use hysteria2's capped windows; a fetch holds a
  bounded window of pieces in memory; the roster is small.

## Warren changes needed

1. **Several listeners per endpoint** (one per group), and `Authorize` given
   the listener key that was called.
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

1. **Group size:** up to about 50 members in v1, so pairwise rekey and a
   single directory shard. A tree scheme (MLS/TreeKEM) is the path past
   that.
2. **Roles:** admin (add, remove, rekey) and member (post, fetch).
3. **Serving:** every member serves what it holds by default; the app can
   turn serving off or cap it per device.
4. **Logs:** the library includes a signed per-member log. Blob
   announcements and app entries (chat, comments) go through it, so apps
   like Murmur get feeds without building their own.
