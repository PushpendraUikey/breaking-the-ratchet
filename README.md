# Breaking the Ratchet

CS6008 — Assignment 3. Investigating a deliberately flawed implementation of a
Double Ratchet + X3DH end-to-end encrypted messaging system, and building
proof-of-concept attacks against it in a controlled Docker lab.

This README records the base concepts the project is built on. Attack code,
measurements, and the report come later.

## The goal of the protocol

The lab implements an instant-messaging protocol in the style of Signal /
WhatsApp. Unlike a TLS-style channel (which secures the link between a client
and a server), this protocol secures messages **end to end**: Alice and Bob
exchange ciphertext through a relay server, and the server cannot read it — as
long as Alice and Bob hold authentic copies of each other's identity keys.

Two security properties matter:

- **Forward secrecy** — compromising a key today does not reveal past messages.
- **Post-compromise (future) secrecy** — after a compromise, the session heals
  and future messages become secure again.

These come from giving every message a fresh key.

## The building blocks

### X3DH — initial key agreement

Before any messages flow, Alice and Bob must agree on a shared secret. Each
party publishes a **prekey bundle** to the server:

- **Identity key (IK)** — long-term. An Ed25519 signing key plus an X25519 DH
  key. Identifies the party.
- **Signed prekey (SPK)** — medium-term X25519 key, signed by the identity key.
- **One-time prekeys (OPK)** — single-use X25519 keys, each with an id. Consumed
  one per new session.

To start a session, Alice fetches Bob's bundle, verifies the SPK signature,
generates an ephemeral key, and combines several Diffie-Hellman results
(DH(IK_A,SPK_B), DH(EK_A,IK_B), DH(EK_A,SPK_B), and — if present — DH(EK_A,OPK_B))
through HKDF into one shared secret. That secret seeds the Double Ratchet. The
first message carries an `init` block so Bob can derive the same secret.

### Double Ratchet — per-message keys

Once seeded, the session advances through two interlocking ratchets:

- **DH ratchet** — each party holds a current DH key pair and sends its public
  key in every message header. When a party receives a *new* public key, it does
  a DH, mixes the result into the root chain, and generates a fresh key pair for
  its next send. A DH ratchet step happens whenever the sending side flips.
- **Root chain** — a one-way KDF chain. Each DH output produces a new root key
  and a fresh chain key.
- **Sending / receiving chains** — symmetric KDF chains that advance once per
  message to produce the message key that encrypts/decrypts that payload. One
  party's sending chain is the other's receiving chain.

Message headers carry `dh` (sender ratchet public key), `pn` (length of the
previous sending chain), and `n` (message number in the current chain) so the
receiver can handle out-of-order and skipped messages.

## Cryptographic primitives (as specified by the lab)

| Role | Primitive |
|------|-----------|
| Diffie-Hellman | X25519 (Curve25519) |
| Signed-prekey signature | Ed25519 |
| Key derivation | HKDF-SHA256 |
| Authenticated encryption | ChaCha20-Poly1305 (IETF, 96-bit nonce) |

## The lab environment

Three containers on a shared Docker network (`as3net`), from the image
`s4ch1n/as3:latest`:

- `as3_server` — in-memory relay on TCP port 9000. Delivery is pull-based:
  `send` queues a frame in the recipient's mailbox, `poll` collects it.
- `alice`, `bob` — clients. Each registers a username, publishes a bundle, and
  can start a session with a peer.

The wire format is newline-delimited JSON, so traffic is readable directly in a
capture (tshark/Wireshark). Each client also prints protocol logs per message.

Server state is in-memory (`docker compose down` resets it). Client keys and
live ratchet sessions persist in the `as3state` volume, so a client that exits
resumes its sessions on reconnect.

See `protocol.md` for the full wire format and reference pseudocode.

## What this project investigates

The implementation is flawed on purpose. The assignment has one modeling task
and three attacks:

- **State diagram** — hand-drawn state transitions for a fixed message sequence
  (DH key pairs, root key, chain keys, message keys, and whether each step is a
  DH ratchet or a symmetric-chain advance).
- **Attack 0 — message-counter manipulation.** A MITM between server and Bob
  modifies the header message number; study how the receiver processes a large
  counter gap and measure the resource impact.
- **Attack 1 — prekey exhaustion.** Study the one-time-prekey lifecycle and what
  happens when Bob's OPK inventory is drained.
- **Attack 2 — malicious server / MITM.** Study the trust model: how identity
  keys are obtained and verified, and whether the server can substitute key
  material undetected.

Each attack is paired with an analysis of the flaw and a proposed fix.

## References

- The Double Ratchet Algorithm — <https://signal.org/docs/specifications/doubleratchet/>
- The X3DH Key Agreement Protocol — <https://signal.org/docs/specifications/x3dh/>
- Double Ratchet Messaging Encryption — Computerphile
- How the Signal Protocol Works (& WhatsApp etc.) — Computerphile
