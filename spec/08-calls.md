# 08. Calls: live voice between friends

Puddle's `docs/calls.md` is the fuller design. What every implementation must agree on is here.

## Who carries a call

The two **Puddles**. Each passes the call to and from its owner's device (its window, or a phone over a leg of its own);
the devices record and play. The media goes between the Puddles over **WebRTC**: ICE, DTLS-SRTP and RTP, with **Opus**
(payload type 111, 48 kHz) for voice.

## Setting it up: over the stream (part 03)

Three signed requests (part 02) between friends with an active stream, each answered with a receipt. They don't go
through a retrying outbox: a call that can't be set up now is missed.

| route | body | answers |
|---|---|---|
| `POST /stream/v1/call/offer` | `{call, sdp, udp}` | `200 {"state":"ringing"}`, `409 busy`, `409 no_calls`, `403 no_stream` |
| `POST /stream/v1/call/answer` | `{call, sdp, udp}` | `204`, `404 no_call` |
| `POST /stream/v1/call/end` | `{call, reason}` | `204`, `404 no_call` |

- `call`: 26 characters of base32 (16 random bytes), chosen by the caller.
- `sdp`: the full offer or answer, candidates included (nothing trickles). It names the DTLS certificate's fingerprint,
  and it arrives signed by the friend's identity: that binds the media to who they are. An implementation must take
  the fingerprint only from a signed `offer` or `answer`, and DTLS must check it.
- `udp`: the UDP port the sender's calls arrive on.
- `reason`: `hung_up`, `declined`, `cancelled`, `no_answer`, `busy` or `failed`; anything else counts as `hung_up`.

## Finding a path

No STUN or TURN server run by a third party. Each side offers the addresses of its own interfaces, and adds the other's
advertised addresses (its signed address record, part 03) at the `udp` port it gave. One UDP port carries all of a
Puddle's calls (ICE multiplexes them by username fragment).

## A phone's leg (part 04)

A phone's calls are carried by its Puddle like any other; the phone has a WebRTC leg of its own to its Puddle for the
sound. That leg is signalled over the owner API, in requests the phone signs with its device key (part 04), each
answered with the Puddle's receipt:

- The phone that starts (`POST /api/v1/calls/start`) or answers (`POST /api/v1/calls/{call}/accept`) a call has it. Only
  that phone may set up a leg for it, and no other device's sound is sent.
- `POST /api/v1/calls/{call}/media` with `{sdp}`: the phone's offer, one Opus track (payload type 111), candidates
  included. Answered `200 {sdp, udp}`: the Puddle's answer and the UDP port its calls use, the same one friends reach.
  `400 not_a_phone` without a device signature, `404 no_call` from another phone or for a call that is over, `400
  bad_sdp`. Asking again replaces the leg.
- The phone adds, as a candidate at `udp`, the address it reaches its Puddle at. No STUN or TURN here either.
- The fingerprints are taken only from these signed exchanges, as on the stream, which binds the leg to the pairing.
- The Puddle passes Opus frames between the leg and the friend's connection without decoding them, on each connection's
  own RTP clock.

## Levee (part 06), later

A Puddle that can't be reached directly needs a relay, which a Levee would be: like a TURN server, it forwards the
encrypted media and sees only its size and timing. Not specified yet; the signalling above needs no change for it,
only candidates at the Levee.

## Not yet

Group calls (a call per pair of members, over the group's connections) and video (a track beside the voice) are planned
in Puddle's roadmap (phase 8) and will be added here when built.
