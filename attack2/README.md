# Attack 2 — Malicious server / MITM (key substitution)

A malicious server defeats end-to-end encryption by **substituting key material**
during X3DH. Because Alice and Bob have **no authentic, out-of-band copy** of each
other's identity key — they learn it only from the server's `fetch_bundle`
response — the server can hand Alice a bundle of its *own* keys, establish a
session with her, decrypt her messages, and (optionally) re-encrypt and forward
them to Bob. The signed-prekey signature is only self-checked against the
identity key *in the same bundle*, so it does not detect substitution.

```
 Alice  <-->  Malicious Server (Mallory)  <-->  Bob
            two separate X3DH sessions, both readable
```

Root cause (see `protocol.md` §3): X3DH binds identity keys only into the
session associated-data; nothing anchors the identity key to the real peer.

## Plan (staged; decide depth after Phase 0)

- **Phase 0 — observe (current, no attack code).** Capture a genuine Alice↔Bob
  session and record the bundle/header layout + whether the client verifies the
  SPK signature. Answers the trust-model questions (A.1–A.4) with evidence and
  locks the wire format the server must reproduce. Tooling: `observe/inspect.py`.
- **Phase 1 — honest malicious server.** A faithful C++/OpenSSL server
  (`register/publish/fetch_bundle/send/poll`) so Alice and Bob talk through it
  normally — proves we are protocol-correct and in-path; logs frames it merely
  forwards (cannot read).
- **Phase 2 — key substitution + plaintext recovery.** Return Mallory's keys on
  `fetch_bundle(bob)`, run `x3dh_respond` on Alice's first frame, **print the
  recovered plaintext**. The confidentiality break.
- **Phase 3 — full transparent MITM (optional).** Also initiate a session to
  Bob, re-encrypt, and relay both directions with ratchet continuation.
- **Phase 4 — fix + report.** Out-of-band identity authentication
  (safety-numbers / TOFU pinning); write `Report.md §5`.

Crypto: **OpenSSL 3** (X25519, Ed25519, HKDF-SHA256, HMAC-SHA256,
ChaCha20-Poly1305-IETF) — already present; no install. Build later with
`-lssl -lcrypto`.

## Phase 0 — observation runbook

Run the **genuine** lab (real `as3_server`) with the clients routed through a
passive logging relay (no `tshark` needed), capture one full session, decode it.

1. Reset and bring up the real server:
   ```sh
   docker compose down -v
   docker compose up as3_server          # T1 — real server on host :9000
   ```
2. Start the passive relay (listens :9200, forwards to the real server :9000),
   capturing raw frames to `cap.jsonl`:
   ```sh
   python3 attack2/observe/relay.py 9200 127.0.0.1 9000 > attack2/observe/cap.jsonl
   # T4 — direction markers print to the terminal; JSON frames go to cap.jsonl
   ```
3. Route the clients **through the relay** (reach the host via
   `host.docker.internal`):
   ```sh
   docker compose run --rm bob \
       /client --server-addr host.docker.internal --port 9200   # T2: publish, then stay
   docker compose run --rm alice \
       /client --server-addr host.docker.internal --port 9200   # T3: message bob, type a line
   ```
4. Decode the security-relevant fields:
   ```sh
   python3 attack2/observe/inspect.py attack2/observe/cap.jsonl
   ```

### What to record (for Report §5.A)

- **Bundle fields + sizes:** `ik_sig`/`ik_dh`/`spk`/`opk` = 32 B (X25519/Ed25519
  keys), `spk_sig` = 64 B (Ed25519 signature); note `opk_id`. (Trust model A.1:
  Alice gets Bob's IK *only* from this server response.)
- **First-frame `header` layout:** the literal header JSON and whether `init` is
  carried only on message 0. This is our read on `serialize(header)` — the exact
  bytes the server must reproduce to compute the AEAD associated data. (Confirmed
  for real once Phase 2 decrypts successfully.)
- **SPK-signature behaviour:** check the initiator's client log for a line like
  `warn: SPK sig NOT verified`. If present, the client does **not** enforce the
  signature → substitution needs no valid signature at all. If absent, we sign
  Mallory's SPK with a Mallory Ed25519 identity (self-consistent bundle).
- **Out-of-band verification:** confirm the client menu offers **no** identity
  fingerprint / safety-number check (Trust model A.4).

## Files

- `observe/relay.py` — passive logging relay (forwards unchanged, dumps raw
  newline-JSON to stdout). Phase-0 capture tool; replaces `tshark`.
- `observe/inspect.py` — decodes captured frames (base64 field sizes, header JSON).
- (Phase 1+ will add `attack2.cpp` + `Makefile`.)
