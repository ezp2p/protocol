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

## Editing and deleting messages

Protocol 14 of `/pond/v1`, the feature `message_edits` (Pond's `docs/design.md`, "Editing and deleting messages"). The Pond
holds the history, so it is the Pond, not the author's Puddle, that changes it; nothing here is signed by the author yet (see
"Later").

- **Edit** (`POST /pond/v1/channels/{channel}/messages/{message}/edit {text?, files?}`): only the author's, and an edit only
  drops files (`files`: the ids kept). A message gains `edited` (ms) once edited.
- **Delete** (`.../delete`): the author's own, or anyone's for a member the channel lets `manage_messages`.
- **Events**: `message_edited` (the message as it reads now) and `message_deleted` (`{id, channel}`), given like any event
  about a channel. A Puddle puts an edit in place of the message it keeps (ignoring one that names another author) and
  forgets a deleted one with its files. The Pond rewrites the earlier events about the message, so a member catching up
  never receives what was taken back: they say it as it reads now, or become `message_deleted`.
- **The message log** is the Pond's: every earlier text, and deleted messages with their files, for members the channel lets
  `view_message_log`, until it is purged (`.../purge`). Members without it see only the message as it reads now, or nothing.
  A Puddle that copied a message before it was edited or deleted may still hold it: deleting is a request to hide, not an
  erase, as between Puddles (Puddle's `docs/storage.md`).

## Replies, reactions and mentions

Protocol 15 of `/pond/v1`, the features `replies`, `reactions` and `mentions` (Pond's `docs/design.md`, "Replies, reactions and
mentions"). As with edits, the Pond holds what a message says and answers for it; nothing here is signed by the author yet.

- **Replies.** A send may name `reply_to`, a message in the same channel that is not deleted. The reply then carries `reply`: a
  quote of that message *as it reads now*, `{id, author, text, files?}` (`text` its first 200 characters, `files` how many it
  carries), or only `{id, deleted: true}` once it is deleted. When the message replied to is edited or deleted, the Pond
  rewrites the earlier events of its replies too, so no quote keeps what was taken back. A Puddle that holds both keeps the
  quote in step from `message_edited` and `message_deleted` itself.
- **Reactions.** `POST .../messages/{message}/react {emoji}` and `/unreact`, for a member the channel lets `add_reactions`.
  An emoji is 1 to 32 bytes of UTF-8 with no ASCII and no control characters, compared byte for byte; each member uses each
  once; a message holds at most 20 different ones. A message carries `reactions`, `[{emoji, count, members}]`. The event
  `message_reactions` (`{id, channel, reactions}`) says a message's reactions as they are now, and the Pond rewrites every
  earlier event about the message to say the same, so whatever a Puddle reads last is right.
- **Mentions.** Written in the text as `<@member id>`, `<@&role id>` and `@everyone`; ids, never names, so a mention still
  reads right after a rename. The Pond works out what a message mentions when it is sent or edited and gives it as
  `mentions` (`{members?, roles?, everyone?}`): members who are in the Pond; roles and everyone only from a member the channel
  lets `mention_everyone`. The Pond tells nobody itself: the member's Puddle receives the message like any other, highlights
  it, and tells its owner when it names them, a role they hold, or everyone. A Puddle tells its owner only of new messages,
  not of edits.

## Later (protocol, not built)

- **Messages signed by their authors**, so a Pond can't forge what a member said (members trust the Pond for what it
  shows today, as they trust a Discord server). The event format would be a Puddle event (part 03): the author's
  signature over exact bytes, naming `kid`. An edit or deletion would then be the author's own `edit` or `redact` event, as
  between Puddles (Puddle's `docs/storage.md`), and a moderator's deletion the Pond's.
- **Roles and moderation** travel as Pond events like any other.
