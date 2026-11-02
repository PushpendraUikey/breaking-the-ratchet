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

## Staged development (what we built, in order)

- **Phase 0 — observe (done).** Captured a genuine Alice↔Bob session through a
  passive relay and decoded it. Established the bundle/header layout and the
  decisive trust-model facts: the SPK signature is **not verified**
  (`warn: SPK sig NOT verified`) and there is **no out-of-band identity check**.
  Tooling: `observe/relay.py`, `observe/inspect.py`.
- **Phase 1 — honest server (folded into Phase 2).** A faithful C++/OpenSSL server
  (`register/publish/fetch_bundle/send/poll` + mailboxes) so the clients behave
  normally and Mallory is in-path.
- **Phase 2 — key substitution + recovery + transparent forward (done).** On
  `fetch_bundle(bob)` return Mallory's keys; `x3dh_respond` on Alice's first
  frame to **decrypt her plaintext**; then `x3dh_initiate` to the real Bob,
  re-encrypt, and deliver — Bob sees a normal message, neither party detects
  anything. See the discovery story below and `Report.md §5`.
- **Phase 3 — full bidirectional MITM (done, DEFAULT mode).** Mallory keeps **two
  persistent Double Ratchet sessions** (one with Alice as responder, one with Bob
  as initiator) and relays *both* directions: decrypt on the session a frame
  arrives from, re-encrypt on the other, forward. DH-ratchet continuation is
  handled on both sessions, so the whole conversation flows while Mallory reads
  **every message both ways**. Verified on the live lab; `Report.md §5.D`.
- **Phase 4 — fix.** Out-of-band identity authentication (safety-numbers / TOFU
  pinning) with Python-style pseudocode; `Report.md §5.E`.

Crypto: **OpenSSL 3** (X25519, HKDF-SHA256, HMAC-SHA256, ChaCha20-Poly1305-IETF)
— already present; build with `-lssl -lcrypto`. Ed25519 is **not** needed because
the client does not verify the SPK signature.

## How we found the AEAD associated-data format

The spec leaves `serialize(header)` / the raw layout of `st.AD` under-specified,
so we discovered the Go client's exact convention empirically:

1. Assumed the spec's literal `ad = st.AD + serialize(header)` (compact header,
   raw `IK‖IK`). An offline **self-test** (`./attack2 --selftest`) passed → crypto
   plumbing correct.
2. The **live run failed** to decrypt → the fault was byte-format compatibility,
   not the maths.
3. Added a **discovery sweep**: compute the first-message key once, then
   brute-force the associated data over `{IK_dh raw/b64, IK_sig raw/b64, reversed,
   none} × {compact, spaced, pn-n-dh, wire+init, empty}` and report the
   combination whose Poly1305 tag validates.
4. **Result:** `prefix = ik_dh raw`, `header = empty` — i.e.
   **`AD = ik_dh_initiator ‖ ik_dh_responder` (64 raw bytes); the header is NOT
   bound into the AEAD.** A successful decrypt also confirmed all X3DH/ratchet
   constants match the spec. (This corrects the Attack-0 mechanism note: counter
   tampering is detected via the key schedule, not an AD mismatch.)

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

## Run the attack

Mallory *replaces* the server, so do **not** run `as3_server`. Reset client state
first so a fresh X3DH actually happens.

### Phase 3 — full bidirectional MITM (default)

```sh
docker compose down -v                                     # reset
cd attack2 && make && ./attack2                            # T1 — malicious server on :9000
docker compose run --rm bob   /client --server-addr host.docker.internal --port 9000   # T2
docker compose run --rm alice /client --server-addr host.docker.internal --port 9000   # T3
```

Have Alice and Bob exchange **several lines back and forth**. On **T1** each line
prints in order as it is recovered:

```
[attack2] AD format discovered: prefix=dh_raw  header=empty
[attack2]  alice -> bob  #1 : "Hello Bob, What are you doing?"
[attack2]  bob -> alice  #1 : "I'm doing good, wbu"
[attack2]  alice -> bob  #2 : "I'm good as well. What are you upto these days?"
```

Both clients display every message normally and detect nothing.

### Phase 2 — single-message recovery (incremental demo)

`./attack2 --phase2` runs the original single-shot path: it decrypts Alice's
**first** message and forwards it, printing `RECOVERED PLAINTEXT …`. Bob's reply
then fails on Alice (`AEAD authentication failed`) — the exact gap Phase 3 closes,
useful to show the "fails authentication" evidence class.

### Offline sanity checks (no lab needed)

- `./attack2 --selftest` — Phase 2 single-message crypto plumbing.
- `./attack2 --selftest-full` — Phase 3 bidirectional, multi-message, including
  each party's DH-ratchet turn (all recovered and delivered intact).

## Files

- `attack2.cpp` — the malicious server (OpenSSL): protocol + key substitution +
  full bidirectional two-session MITM (default) + Phase 2 single-shot (`--phase2`)
  + AD-format discovery sweep + `--selftest` / `--selftest-full`.
- `Makefile` — `make` / `make clean` (links `-lssl -lcrypto -pthread`).
- `observe/relay.py` — passive logging relay (forwards unchanged, dumps raw
  newline-JSON to stdout). Phase-0 capture tool; replaces `tshark`.
- `observe/inspect.py` — decodes captured frames (base64 field sizes, header JSON).
