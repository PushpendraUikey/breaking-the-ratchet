# Attack 0 — Message-counter manipulation

MITM (Mallory) between `as3_server` and Bob. Inflate the header counter (`n` /
`pn`) on a frame addressed to Bob to force a large skip gap, then measure the
resource impact on Bob's client.

## Files

- `attack0.cpp` — the MITM proof-of-concept.
- `Makefile` — `make` to build, `make clean` to remove the binary.
- `measure/capture.sh` — sample Bob's CPU/mem via `docker stats` into a CSV.
- `measure/plot.py` — plot the CSV.

## How it works

Mallory accepts Bob's connection, dials the real server, and relays both
directions as newline-delimited JSON.

- **Bob → server** is forwarded unchanged.
- **Server → Bob** is buffered to whole frames and passed through the tamper
  step: any `type:"frames"` line addressed to the target has its header message
  number `n` (and optionally `pn`) inflated by `--gap`, then re-framed and
  forwarded. Every rewrite is logged (`n X -> Y`).

A frame whose `n` is far ahead of Bob's current receive counter makes his client
run the skip-key loop (deriving and storing one message key per skipped number)
*before* the AEAD tag is checked — so the work happens even though the forged
frame ultimately fails to decrypt.

## Build & flags

```sh
make
```

| Flag          | Effect                                                        |
|---------------|---------------------------------------------------------------|
| `--gap N`     | add `N` to the header `n` of frames to the target (0 = off)   |
| `--pn`        | also inflate `pn` (adds a second gap after a DH-ratchet step) |
| `--target U`  | only tamper frames whose `to` is `U` (default `bob`)          |
| `-v`          | verbose: also log poll traffic                                |

With no `--gap`, the binary is a transparent logging relay (Step-1 behaviour).

Listen/forward addresses are compile-time constants in `cfg::` at the top of
`attack0.cpp` (default: listen `0.0.0.0:9200`, forward `127.0.0.1:9000`).

## Workflow

1. Bring up the lab; position Mallory so Bob reaches the server through it
   (point Bob's client at Mallory's listen port, e.g. `--server-addr
   host.docker.internal --port 9200`).
2. Establish an Alice↔Bob session so a real receiving chain exists on Bob.
3. In one terminal start the sampler:
   `measure/capture.sh bob 60 > measure/stats.csv`.
4. In another, run `./attack0 --gap <N>` and have Alice send a message to Bob
   so a frame flows through the tamper step.
5. Sweep `<N>`, re-run, and `python3 measure/plot.py measure/stats.csv`.

Clear Bob's client state between runs (`docker compose down -v`, or
`docker volume rm as3state`) so each gap starts from a clean ratchet.

## Open questions to answer

- Does modifying `n`/`pn` break AEAD auth, or does the receiver do the skip work
  before the auth check fails?
- Is there a per-session cap on stored skipped keys (e.g. `MAX_SKIP`)? Is the
  cap checked *before* the loop, so an over-large gap aborts cheaply? Is state
  rolled back on a failed decrypt, or do the derived keys persist?
- How far can the gap be pushed, and what is the CPU/memory cost at each step?
</content>
</invoke>
