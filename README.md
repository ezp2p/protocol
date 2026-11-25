# The Puddle Protocol

What every ezp2p program says on the wire, written down once, so that programs built apart, in their own code and
upgraded at their own pace, still understand each other.

## The specification

The protocol's text is on the website wiki: **[Protocol](https://www.ezp2p.org/wiki/protocol/)**, one page per part
(overview, identity, signatures, streams, devices, ponds, levee, drip, calls, sealing, letters). Its source is in
`ezp2p/website` under `src/wiki/protocol/`. Why the protocol is its own repository, and why it has a shared library,
is under [Decisions: Protocol](https://www.ezp2p.org/wiki/decisions/protocol/).

A change to the wire changes the wiki page, here, and a vector together. Code and specs that name `spec/NN-name.md`
mean the wiki page `protocol/name`.

## What is here

- `lib/`: **libpuddle-proto**, the protocol's bytes in C for every program (`lib/include/puddle_proto.h`). Puddle, Pond
  and Levee carry this repository as the submodule `third_party/protocol`.
- `vectors/`: test vectors: fixed keys, ids, signed requests and receipts, each with the answer an implementation must
  give. Every implementation's tests load them (Puddle's `protocol_vectors` test). A change to the wire changes a vector.

Work still to do is on the [project board](https://github.com/orgs/ezp2p/projects/1).
