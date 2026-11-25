# Decisions

## Do we need a separately defined protocol? Yes: a specification and test vectors. Not (yet) a shared library.

*Decided 2026-11-12, to be reviewed by the owner.*

### Why a protocol of its own

- **There are already two implementations.** Pond "shares no code with Puddle" (its README): it checks key chains and
  request signatures in its own `src/identity.cpp` and `src/reqsig.cpp`, written from Puddle's documentation. Levee
  will be a third and Drip a fourth. Programs that must agree byte for byte need one text that says what the bytes are,
  owned by none of them.
- **Puddle's documents are not that text.** They mix the wire with how Puddle happens to be built (its folders, its
  outbox schedule, its app). A Pond or Levee author has to dig the rules out, and a Puddle change can move a rule
  without anyone noticing that the Pond now disagrees.
- **The parts now depend on each other.** Two examples from this week:
  - Proving who answers (receipts, Puddle phase 6) changes what every responder must send, Ponds included, and it
    breaks a Puddle behind a Levee unless the Levee is designed for it (`spec/06-levee.md`). That is a cross-project
    decision, and it needed a cross-project place to be made.
  - A Puddle pins a Pond's TLS certificate because Ponds don't sign receipts, so a renewed certificate cuts every
    member off. The fix (Ponds sign receipts) is a protocol change both sides must make.
- **Versioning needs one owner.** Pond already versions by path (`/pond/v1`) and advertises `protocol` and
  `features`. Puddle versions by path (`/stream/v1`). Both need the same rules for what may change within a version;
  `spec/00-overview.md` states them once.

### Why test vectors

A specification can be misread. Vectors can't: fixed inputs, the exact expected outputs, and the answer a checker must
give (accept, or which refusal). Each implementation's own tests load `vectors/*.json` from a checkout beside it
(Puddle's `protocol_vectors` test looks in `../protocol`, as Pond's end-to-end test looks for `../puddle`), so any
disagreement fails a build instead of a conversation. The vectors were made by Puddle's code, which is the reference
until something here says otherwise.

### A shared library after all: libpuddle-proto (2026-11-21)

Until Levee, the answer was no: Puddle and Pond were built apart on purpose, and two implementations agreeing proved the
text complete. Levee made it three, and the owner chose the library first (2026-11-21). So `lib/` here is
**libpuddle-proto**: C-callable, OpenSSL 3 only, no other dependency, built with CMake and pulled into a program with
`add_subdirectory` (each program carries this repository as a git submodule). It holds ids, key chains, request
signatures, receipts, custody receipts, sealing and pieces; nothing that is one program's own (keeping keys, phrases,
routes, storage). Puddle, Pond and Levee all use it.

What keeps the text honest now that one implementation serves all three: the vectors stay, and the library is checked
against them on every build (`lib/tests/proto_test.cpp`), so a change to the bytes still has to change a vector.

### Where this lives

`ezp2p/protocol` as its own repository, so it is versioned and reviewed apart from any one program. Each program's
`docs/protocol.md` says which parts it implements and links here. (Made locally on 2026-11-12; it still needs a
repository on GitHub, which only the owner can create.)

## Receipts through a Levee: the Puddle vouches for its front

See `spec/06-levee.md`. A Levee terminates TLS for the Puddle behind it, so a receipt over the Puddle's own certificate
would look like interception. Decided: a Puddle answering through its Levee signs its receipt over **the Levee's**
certificate (it knows it: it connected to it), and its address record names the Levee's key. A Levee answering for an
offline Puddle signs a **custody receipt** with its own key, which senders accept only for a Levee that Puddle has
announced. Nothing in the existing receipt changes; one new header and one new address-record field are added.

## Ponds should sign receipts

See `spec/05-ponds.md`. Built: Ponds answer members with the same `X-Puddle-Receipt` Puddles use, signed by the
Pond's key. A Puddle stops pinning a Pond's certificate, and a Pond can renew its certificate (Let's Encrypt, say)
without cutting everyone off. Advertised as the feature `receipts` (protocol 3 of `/pond/v1`), so Puddles keep
pinning Ponds that don't have it. Pond checks itself against the vectors too, so there are now two implementations of
part 02 that agree.

## TLS is transport only (2026-11-18, design: `spec/09-sealing.md`)

Decided with the owner: **nothing in the protocol may depend on a TLS certificate.** Most people will run a Puddle or
a Pond behind a reverse proxy, many on Let's Encrypt certificates that change every few months, and some will do
stranger things still. Receipts naming the certificate (part 02) made each of those break: a proxy looks like
interception, and a renewal needs a restart.

The certificate was only in receipts because TLS was the only thing keeping bodies private. So the fix is to make the
keys do that too: every request body is sealed (HPKE, RFC 9180) to the recipient's encryption key, every answer back to
the caller, and receipts stop naming a certificate. Then a certificate can be anything, and change any time, and a
proxy or a Levee sees routes and sizes but no contents. Open questions, with recommendations, are at the end of part 09.

## Levee's open questions (2026-11-25)

See `spec/06-levee.md`, "Settled with the owner". Decided with the owner: one Levee for one Puddle, both ways, and no
spare (no gain worth the complexity); friends always reach a Puddle through its Levee, never directly; certificate
pinning is gone with part 09. What a Levee takes in custody and then gives up on (its spool's age limit, or the Puddle
detaching) is **told to both ends**: the sender gets a notice signed by the Levee (`POST /stream/v1/undelivered`) and
counts the request as not delivered, and the Puddle gets a list on its next attach. The sender's owner then resends or
deletes the message once the recipient is back. This adds `addresses` and `levee` to the entries of `peers`, so the
Levee can reach a sender, including one behind a Levee of its own.

The section "Receipts through a Levee" above is superseded: since part 09 no receipt names a certificate.
