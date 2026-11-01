# Attack 0 — Message-counter manipulation

MITM (Mallory) between `as3_server` and Bob. Inflate the header counter (`n` /
`pn`) on a frame addressed to Bob to force a large skip gap, then measure the
resource impact on Bob's client.

## Files

- `attack0.cpp` — the MITM proof-of-concept (skeleton).
- `Makefile` — `make` to build, `make clean` to remove the binary.
- `measure/capture.sh` — sample Bob's CPU/mem via `docker stats` into a CSV.
- `measure/plot.py` — plot the CSV.

## Workflow (to fill in)

1. Bring up the lab; position Mallory so Bob's traffic flows through it.
2. Establish an Alice↔Bob session so a real sending chain exists.
3. Run `./attack0` to intercept a frame to Bob and inflate the counter.
4. In parallel: `measure/capture.sh bob 60 > measure/stats.csv`.
5. Sweep the gap, re-run, and `python3 measure/plot.py measure/stats.csv`.

## Open questions to answer

- Does modifying `n`/`pn` break AEAD auth, or does the receiver do the skip work
  before the auth check fails?
- Is there a per-session cap on stored skipped keys? Is state rolled back on a
  failed decrypt?
- How far can the gap be pushed, and what is the CPU/memory cost?
