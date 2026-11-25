# Test vectors

Fixed inputs and the answer every implementation must give. Load them in your tests from a checkout of this repository
beside yours (`../protocol/vectors`).

| File | Spec | What an implementation must do |
|---|---|---|
| `devices.json` | 01, device ids | from each `seed`, make the Ed25519 key: its `public_key`, device `id` and six-digit `check` must match |
| `levee.json` | 01, 06 | from the `seed`, a Levee's Ed25519 `public_key`, its `id` and its sealing key (`seal_public_key`); and `custody`: check each `header` as a custody receipt from that Levee for the Puddle `for`, the request's `nonce` and the SHA-256 of `body`; say `ok`, `missing`, `wrong_key` or `bad` |
| `signatures.json` | 02 | `requests`: authenticate `header` for a request with that `method`, `target` and `body`, as the Puddle `checked_by` (or, with `accepts_any`, as anyone: recipient `*`), at `now_ms`, knowing only `sender`'s key; say `ok`, `reject` (the plain `404`) or `clock_skew`. `receipts`: check `header` as the caller of a request with that `nonce`, given `status`, `body` and the certificate it saw (`seen_fp`), knowing `responder`'s key; say `ok`, `missing`, `wrong_key`, `bad` or `other_cert` |

Keys are given as hex in the files; in the headers they are as `spec/02-signatures.md` says.

They were made by Puddle (`tests/protocol_vectors_test.c`, with `PUDDLE_WRITE_VECTORS=<this folder>`), which checks
itself against them on every build. Pond checks itself against `signatures.json` too (`tests/protocol_test.cpp`). Making them again changes every signature (new nonces, a new identity), so it is
done only when the protocol changes, and every implementation then checks the new ones.

`levee.json` is made by libpuddle-proto (`lib/tests/proto_test.cpp`, with `PP_WRITE_VECTORS=<this folder>`), which also
builds key chains from fixed seeds and checks good and broken ones.

Not covered yet: key chains as a vector file, address records, Pond ids. Each needs a vector file before a second implementation relies on it.
