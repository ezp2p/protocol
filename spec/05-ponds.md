# 05. Ponds: a Puddle and a community server

A **Pond** is a community server, like a Discord server: channels, many members, history kept **on the Pond**. A
member's Puddle caches what it has seen. There is no peer to peer here: members talk to the Pond, never to each other
through it, and the Pond never calls a Puddle. The routes are `/pond/v1/...`; Pond's `api/pond.yaml` and
`docs/design.md` have them in full.

## Joining and being a member

- **Invite links**: `pond://<address>?invite=<26 base32>&k=<the Pond's sealing key, 52 base32>` (part 09: the join is
  sealed to it). A used-up, expired, revoked or unknown invite is `404`. An invite without `k` is the old kind and is
  refused by the Puddle.
- **Joining** (`POST /pond/v1/join`): `{invite, chain, profile}`, signed for recipient `*` (the Puddle doesn't know the
  Pond's id yet), proven by the chain in the body. The answer carries the Pond's id, name, channels and event cursor.
- **Every other route** is signed for the Pond's id by the member's current key (part 02). A non-member gets `404`.
- **Keys**: a member that rolls its keys sends its new chain to `POST /pond/v1/keys`.
- **Events**: one request held open on `GET /pond/v1/events?after=<cursor>` (up to 25 seconds). Because the Puddle
  always makes the connection, this works from behind NAT and through a Levee.
- **What a Pond can do** is in `/pond/v1/info`: `protocol` (a number) and `features` (`files`, ...).

## Proving who answers, and sealing

Protocol 5 of `/pond/v1`, the features `receipts` and `sealed`. The Pond's `pond` object in `/info` (and in a join's
answer) gives its Ed25519 public key as `key` (hex), whose SHA-256 in base32 is the Pond's id, and its sealing key as
`seal_key` (hex), derived from the same seed (part 09). The join's `seal_key` must be the invite's `k`.

- **Every request is sealed** to `seal_key` (part 09); one that isn't is `400 not_sealed` once it has authenticated.
- **Every answer to an authenticated member**, and the answer to a join that worked, is sealed back and carries the Pond's
  receipt (part 02, v2): a Puddle believes an answer only with it.
- **A request the Pond opened but refused** (someone who isn't a member) gets the same `404` as an unknown path, sealed
  under that request's key and unsigned. Only the Pond could seal it, so a removed member can tell it is the Pond saying
  so; a plain `404` (or one that won't open) proves nothing, and the Puddle shows the Pond as `not_proven` and keeps
  trying.
- **No certificate** is pinned, proven or compared. A Pond behind a reverse proxy, or renewing a Let's Encrypt
  certificate, needs nothing from its members or from them.

## Later (protocol, not built)

- **Messages signed by their authors**, so a Pond can't forge what a member said (members trust the Pond for what it
  shows today, as they trust a Discord server). The event format would be a Puddle event (part 03): the author's
  signature over exact bytes, naming `kid`.
- **Roles and moderation** travel as Pond events like any other.
