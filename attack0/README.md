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

| Flag          | Effect                                                              |
|---------------|--------------------------------------------------------------------|
| `--gap N`     | add `N` to the header `n` of frames to the target (0 = off)        |
| `--accum`     | climb `n` by `N` per frame within a chain (reset on a new `dh`)    |
| `--flood K`   | fan one genuine frame into `K` stepped copies (`n = N, 2N, …, KN`) |
| `--pn`        | also inflate `pn` (adds a second gap after a DH-ratchet step)      |
| `--target U`  | only tamper frames whose `to` is `U` (default `bob`)               |
| `-v`          | verbose: also log poll traffic                                     |

With no `--gap`/`--flood`, the binary is a transparent logging relay (Step-1
behaviour). `--flood`/`--accum` default the step `N` to 1000 if `--gap` is unset.

### Modes

- **Single (`--gap N`)** — one skip of `N − Nr` per frame. Cost per frame is
  bounded by the receiver's skip limit, so this measures the *per-frame* curve.
- **Accumulate (`--accum`)** — successive frames in the same chain get
  `n = N, 2N, 3N, …`, so each one forces a fresh `~N` skip even when a fixed
  offset would land below `Nr` and do nothing.
- **Flood (`--flood K`)** — from a *single* genuine Alice message, Mallory emits
  `K` separate `frames` responses with `n = N, 2N, …, KN`, making Bob derive and
  store `~K·N` message keys in one burst. This is the mode for the impact plot:
  it drives memory up steeply without needing Alice to keep typing, and at large
  `K·N` can push Bob's container to OOM.

Listen/forward addresses are compile-time constants in `cfg::` at the top of
`attack0.cpp` (default: listen `0.0.0.0:9200`, forward `127.0.0.1:9000`).

## Terminal layout

Mallory must be listening before Bob connects, because Bob routes *through* it.
Use five terminals; all paths are relative to the repo root except where noted.

| Terminal | Role | Start command |
|----------|------|---------------|
| T1 | server  | `docker compose up as3_server` |
| T2 | Bob     | `docker compose run --rm bob /client --server-addr host.docker.internal --port 9200` |
| T3 | Alice   | `docker compose run --rm alice` |
| T4 | Mallory | `cd attack0 && make && ./attack0 <flags>` |
| T5 | sampler | `cd attack0 && ./measure/capture.sh "$(docker ps --format '{{.Names}}' \| grep -m1 bob)" 90 > measure/<name>.csv` |

In the clients: choose `1) message user`, then the peer name. Bob then **waits**
(just polls); Alice is the trigger and sends exactly one line when told to.

Reset between runs so each starts from a clean ratchet:
`docker compose down -v` (full reset) or `docker volume rm as3state` (client
state only).

## Scenarios

### Scenario 0 — sanity: transparent relay (no tampering)
```sh
cd attack0 && make && ./attack0            # or add -v to see poll traffic
```
Bring up T1/T2/T3, exchange a few messages. Mallory logs every frame and
forwards unchanged; Alice and Bob chat normally. Proves Mallory is correctly
in-path before any tampering.

### Scenario 1 — boundary probe: find/disprove the skip cap
Run Mallory with a single-frame gap and send **one** Alice→Bob message; read
Bob's error line. Reset (`docker compose down -v`) between each:
```sh
./attack0 --gap 999      # expect: AEAD authentication failed (work done)
./attack0 --gap 1001     # if still AEAD fail -> MAX_SKIP is NOT 1000
./attack0 --gap 5000     # sweep upward; watch for "too many skipped messages"
```
Interpretation: the cost is the gap `n − Nr` at receipt, not the absolute `n`.
If "too many skipped messages" never appears, the skip loop is effectively
unbounded (our observed result).

### Scenario 2 — impact measurement (the plots)
One genuine Alice message, amplified by flood, sampled by `docker stats`.
Per data point: reset, start Mallory (T4), start the sampler (T5), then send one
Alice line (T3). Name each CSV `stats_<label>_<total>.csv`:
```sh
# per-frame curve (sweep the gap):
./attack0 --gap 1000000        # -> measure/stats_single_1000000.csv
# impact burst (K=100 fixed, sweep the step; total keys = K*N):
./attack0 --flood 100 --gap 10000     # 1M   -> measure/stats_flood_1000000.csv
./attack0 --flood 100 --gap 100000    # 10M  -> measure/stats_flood_10000000.csv
./attack0 --flood 100 --gap 250000    # 25M  -> expect OOM-kill of Bob
```
Memory is the cleaner signal — stored keys persist (no rollback), so compare
Bob's memory just before vs. after the message, and note the plateau value.

### Plotting
```sh
cd attack0/measure
python3 plot.py stats_flood_10000000.csv flood_10000000.png   # one run vs time
python3 plot.py --sweep sweep.png                             # peak CPU/mem vs gap
```
`--sweep` scans every `stats_<label>_<N>.csv` in the folder, takes each run's
peak CPU and memory, and plots them against the trailing `N` on a log x-axis.
(Needs `matplotlib`: `python3 -m pip install --user matplotlib`.)

## Findings

Full analysis, measurements, and the proposed fix are in the top-level
`Report.md` (Section 3). In short: the header is AEAD-authenticated so no forged
frame is accepted, but the receiver performs **unbounded** skipped-key
derivation/storage *before* the auth check and never rolls it back on failure —
so one tampered frame forces attacker-controlled CPU and permanently-held memory
(measured: 10M keys → 2.6 GiB held + ~40 s CPU saturation from a single message).
