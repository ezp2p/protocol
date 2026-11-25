# 11. End to end: message bodies encrypted where they are written

**Status:** draft, 2026-11-25, for Puddle issue 41. Not built. The choices marked *(owner, 2026-11-24)* were made by
the owner; the rest are recommendations, listed again under "Open decisions".

## Why

Part 09 seals every **request** to the next party's key, so TLS is transport only. That is real encryption with a
dedicated key, but it protects a hop, not a message:

- The body is sealed by whichever program sends the request, and opened by whichever program receives it. A phone
  seals to its own Puddle, which opens it; that Puddle seals again to the recipient's Puddle, which opens it.
- Nothing about the **message itself** says who may read it. A message is plain text inside each request, so anything
  that ever carries it outside a sealed request (a future relay, a member passing group history on, a Pond holding a
  letter, a backup) has to be secured separately each time.

This part encrypts the message **once, on the device that writes it**, to the people in the chat. Every hop after
that carries ciphertext, and part 09's sealing still wraps each request around it.

## Who the ends are *(owner, 2026-11-24)*

**An end is a Puddle, together with its clients.** A person's own Puddle is trusted: it is theirs, it keeps their
chats, and it reads their messages. A phone (or a desktop app paired to a Puddle somewhere else) is a client of that
Puddle, and it holds the same key.

- **One encryption key per Puddle.** This is the X25519 key already in every chain (part 01). There are no keys per
  chat, per group or per device.
- **Clients hold it too.** A paired client is given the Puddle's encryption key pair (below). This reverses the
  decision in Puddle's `docs/identity.md`, "Devices", that a phone holds none of the keys, and puts back what the same
  document says earlier: the daily keys "are what a phone is given". The signing key stays on the Puddle; a client
  does not sign events.
- **Who can read a message:** the Puddles of the people in the chat, and those Puddles' clients. **Who can't:** a
  Levee, a Pond carrying a letter, a reverse proxy, anyone in the middle, and any Puddle not in the chat (including
  one that passes group history on, should that ever happen).

**Pond channels are not covered** *(owner, 2026-11-24)*. A Pond reads its channels, as a Discord server does, so it
can moderate, keep history, and show it to new members. The app says so where it matters. Direct messages carried by
a Pond (letters) **are** covered.

## What is encrypted

A chat event (Puddle's `docs/storage.md`) keeps its envelope readable, so Puddles can route, bucket, order, dedupe and
work out group membership. What a person wrote is encrypted.

| Readable (envelope) | Encrypted (content) |
|---|---|
| `type`, `chat`, `sender`, `ts`, `ref` | a `message`'s text, its caption and its files (names, sizes, previews, keys) |
| membership: `member.invite`, `member.join`, `member.leave` and who they name | an `edit`'s new text and files |
| a `redact` (it has no content) | a group's name (`chat.create`'s `name`, `chat.rename`'s `body`) |

A Puddle in the chat can open the content, so it still searches, shows notifications and keeps history as it does
today. What changes is that nothing else ever holds the plain text.

## The construction *(owner, 2026-11-24: simple HPKE now)*

The suite is part 09's: HPKE (RFC 9180) base mode, `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, `ChaCha20-Poly1305`,
the same code (`libpuddle-proto`'s `pp_hpke_*`).

To encrypt an event's content, the writer:

1. Puts the content fields in one JSON object, the **content** (for a message: `{"body": ..., "files": [...]}`).
2. Picks a random 32-byte **content key** `K` and a random 16-byte **nonce** `n`.
3. Encrypts the content with ChaCha20-Poly1305 under `K`, with an all-zero 12-byte nonce (`K` is used once) and

       aad = puddle-e2e-v1\n<chat>\n<sender id>\n<type>\n<base64 of n>

4. For **each recipient Puddle**, wraps `K` with an HPKE sender context to that Puddle's current encryption key, with

       info = puddle-e2e-v1\n<sender id>\n<recipient id>\n<chat>\n<base64 of n>

   and `aad` empty. The recipients are every member of the chat **and the sender's own Puddle**, so the sender's other
   clients can read it too.
5. Replaces the content fields in the event with one field, `e2e`:

       "e2e": {"v":1, "n":"<b64 16>", "ct":"<b64>",
               "to":[{"id":"<user id>", "kid":"<hex SHA-256 of the encryption key used>", "enc":"<b64 32>", "key":"<b64 48>"}, ...]}

The event is then signed by the sender's Puddle (part 03, unchanged), over the bytes as they now are: the signature
covers the ciphertext. It is stored and sent exactly as signed, as every event is.

To read one, a recipient finds its own `id` in `to`, opens `key` with its private key for that `kid` (the current one, or
one it has rolled away from: see "Key rolls"), and opens `ct` with `K` and the `aad` rebuilt from the envelope. Because
the `aad` and `info` name the chat, the sender, the type and the nonce, content can't be moved to another event, chat
or sender, and a recipient can't be swapped in.

**Size.** Each recipient adds about 250 bytes of JSON. A full group (50 members) adds about 12.5 KiB to an event, within
`PUDDLE_EVENT_MAX_BYTES` (32 KiB) only if that limit is raised for the `e2e` field, or the per-recipient entry is
shortened (see "Open decisions", 3).

**What this does not give:** forward secrecy. Whoever later gets a Puddle's private encryption key can read every
message sent to it while that key was current. Part 01's key roll is the remedy for a lost key; a ratchet can come later
as `"v":2` without touching the envelope.

## Files

Each file is encrypted by the writer with its own random key (ChaCha20-Poly1305 in 64 KiB records, as part 09's
answers), before it leaves the device. Its key, hash and name are in the encrypted content. Puddles, Levees and Ponds
store and pass on ciphertext; a reader decrypts what it fetches. This is what Pond letters already do for their
files (Puddle's `docs/pond-dms.md`); this part makes it the rule for every chat.

## Who encrypts

**Whatever composes the message.**

- **A client** (a phone, or an app paired to a Puddle elsewhere) encrypts the content itself, with the recipients'
  keys, and sends the event's content to its Puddle already encrypted. The Puddle fills in nothing it would need to
  read: it checks the `to` list names every member of the chat and its own id, and nobody else (otherwise `400
  bad_recipients`, with the members it expected), then signs and sends the event.
- **The Puddle's own window** (the desktop app talking to a Puddle on the same machine over `127.0.0.1`, part 09,
  "The owner API") is the Puddle. It may hand the Puddle plain text, and the Puddle encrypts. Nothing leaves the
  machine unencrypted either way.

A client needs the recipients' encryption keys. It asks its own Puddle for the chat's members and their keys
(`GET /api/v1/conversations/{id}/keys`, new), and checks each key against that member's chain as it already checks its
own Puddle's.

## Clients get the key

- **Pairing (part 04).** When the owner accepts a device, the next `GET /device/v1/status` answer to it carries the
  Puddle's encryption key pair, and the private halves of the keys it has rolled away from (`enc_keys`: a list of
  `{kid, private}`). That answer is sealed under the request's own answer key (part 09), so only that phone and its
  Puddle can open it.
- **The phone keeps them** in the platform's key store (Android Keystore, iOS Keychain), never in a plain file.
- **A key roll** (part 01) sends the new pair the same way, on each device's next `status`.
- **Revoking a device** stops its requests, but the phone still has the key. So when a device is revoked as lost or
  stolen, the app offers to roll the keys straight after, and says why. (This is already the advice for stolen daily
  keys.)

## Receiving and storing

- A Puddle that receives an event checks the signature as today, then opens the content. Content that won't open
  (no entry for it, or the wrong key) is kept but shown as "couldn't be read", and the sender is told (`undecryptable`
  in the delivery receipt), so a stale key shows up rather than vanishing.
- **Stored as signed**, so ciphertext at rest. The Puddle may keep a plain-text index for search beside it; whether
  that index is itself encrypted is Puddle's `discuss-later.md`, item 3, and not this part.
- **Clients** fetch events as stored and decrypt them, keeping only what they show (recent chats), as now.

## Key rolls

A message is encrypted to the key the sender holds for each recipient. If the recipient has rolled since, part 09
already refuses the request with `409 stale_key` and the new chain; the sender's Puddle passes the new key to the
client that wrote the message, which re-wraps `K` for that recipient (the content and `n` are unchanged) and the event
is signed again. A Puddle and its clients keep the private keys they have rolled away from, so history stays readable.

## Where each kind of chat stands

| Chat | Encrypted to | Carried by |
|---|---|---|
| Direct message | the two Puddles | streams (part 03), through a Levee when there is one (part 06) |
| Group | every member's Puddle | streams, scoped streams, Levees |
| Pond letter (DM through a Pond) | the two Puddles | the Pond (part 10). The letter keeps its own sealing; the event inside it now has `e2e` too |
| Pond channel | not encrypted *(owner)* | the Pond, which reads it |

Levees change nothing: they already carry sealed requests, and now the event inside is encrypted as well.

## Transition

Nothing has been released, so, as part 09 did: **in place, no plain-text fallback**. An event with a plain `body` (or
group name) from a peer is refused once both sides have this; until then the app shows that peer as "not encrypting
end to end yet". Existing history stays as it is on each Puddle; it is never sent again, so nothing needs re-encrypting.

## What changes in the other parts

- **01**: the encryption key is described as "a Puddle's key for end-to-end encryption, shared with its clients"
  (today's text already says "end-to-end encryption between Puddles", which becomes true).
- **03**: events: content in `e2e`. "Encrypted end to end" under "While connected" now points here.
- **04**: the `status` answer carries `enc_keys` to an accepted device; `bad_recipients`.
- **10**: the letter's event has `e2e`.
- **Puddle's docs**: `identity.md`, "Devices" (phones hold the encryption key); `roadmap.md`, "Later" (message bodies
  are encrypted end to end; Pond channels deliberately are not); `levee.md` is already right.
- **vectors**: `e2e.json`: an event's content encrypted to two recipients from fixed keys and a fixed `K` and `n`, and
  the refusals (wrong `aad`, a recipient swapped, a missing entry).

## Building it

1. The construction and vectors in `libpuddle-proto`, beside part 09's HPKE.
2. Puddle: encrypting in the Puddle for its own window; opening, storing, `undecryptable`; groups and letters.
3. Phones: the key at pairing and on rolls, encrypting and decrypting in the app, `conversations/{id}/keys`.
4. Files encrypted by the writer.
5. Refusing plain bodies.

## Open decisions

1. **Clients sign events too?** Recommended: not now. The Puddle signs, as today; a client is trusted the way its
   Puddle is. Giving clients the signing key would let a stolen phone speak as the owner as well as read.
2. **The Puddle's own window sends plain text over `127.0.0.1`.** Recommended: yes, since it is the same machine and
   the same trust. The alternative (the desktop app always encrypts, even to its own Puddle) costs little but means
   the window needs the key file.
3. **Group size.** Recommended: raise the event limit for `e2e` to fit 50 recipients rather than shorten the entries
   (dropping `id` in favour of `kid` alone would save about 70 bytes each but make a missing entry harder to explain).
4. **Encrypting group names.** Recommended: yes, as above. The cost is that an invitation shows the name only once the
   invitee's Puddle has opened it, which it can, since the invitation is encrypted to them.
