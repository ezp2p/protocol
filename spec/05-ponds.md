# 05. Ponds: a Puddle and a community server

A **Pond** is a community server, like a Discord server: channels, many members, history kept **on the Pond**. A
member's Puddle caches what it has seen. There is no peer to peer here: members talk to the Pond, never to each other
through it, and the Pond never calls a Puddle. The routes are `/pond/v1/...`; Pond's `api/pond.yaml` and
`docs/design.md` have them in full.

## Joining and being a member

- **Invite links**: `pond://<address>?invite=<26 base32>`. A used-up, expired, revoked or unknown invite is `404`.
- **Joining** (`POST /pond/v1/join`): `{invite, chain, profile}`, signed for recipient `*` (the Puddle doesn't know the
  Pond's id yet), proven by the chain in the body. The answer carries the Pond's id, name, channels and event cursor.
- **Every other route** is signed for the Pond's id by the member's current key (part 02). A non-member gets `404`.
- **Keys**: a member that rolls its keys sends its new chain to `POST /pond/v1/keys`.
- **Events**: one request held open on `GET /pond/v1/events?after=<cursor>` (up to 25 seconds). Because the Puddle
  always makes the connection, this works from behind NAT and through a Levee.
- **What a Pond can do** is in `/pond/v1/info`: `protocol` (a number) and `features` (`files`, ...).

## Proving who answers: receipts from Ponds

Protocol 3 of `/pond/v1`, the feature `receipts`. The Pond's `pond` object in `/info` (and in a join's answer) gives its
Ed25519 public key as `key` (hex); its SHA-256, in base32, is the Pond's id, so a Puddle can check it belongs.

A Pond with `receipts` signs a receipt (part 02) on **every answer to an authenticated member**, and on the answer to a
**join that worked**, with its key, over its own TLS certificate. Nothing anyone could be sent carries one: not the
plain `404`, nor a join that failed for any reason. A Puddle that sees `receipts` in `features`:

- keeps the key, and from then on **checks the receipt on every answer**, believing it only over the certificate the
  receipt names;
- **stops pinning**: shown a certificate the Pond hasn't proven, it asks `GET /pond/v1/info` over it (the handshake:
  it changes nothing) and, if the receipt names that certificate, carries on with it. If it can't be proven, it sends
  nothing (Puddle shows this as `not_proven`);
- treats the plain, unsigned `404`, over a certificate the Pond has proven, as the Pond no longer having it as a member;
- never goes back to pinning: once a Pond signs, a later answer saying otherwise is not believed.

A Pond without the feature is pinned to the certificate seen at join, as before (`certificate_changed` when another is
shown). A Puddle that joined it then learns its key from the first `/info` that offers `receipts`, over the pinned
certificate. Pond reads its certificate once at start, so the `fp` it signs over is the one it serves.

## Later (protocol, not built)

- **Messages signed by their authors**, so a Pond can't forge what a member said (members trust the Pond for what it
  shows today, as they trust a Discord server). The event format would be a Puddle event (part 03): the author's
  signature over exact bytes, naming `kid`.
- **Roles and moderation** travel as Pond events like any other.
