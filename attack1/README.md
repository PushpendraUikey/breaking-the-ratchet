# Attack 1 — Prekey Pogo (one-time-prekey exhaustion)

Mallory is an **ordinary client** (no special network position). Bob has
published a prekey bundle and gone offline. Each `fetch_bundle` for Bob hands out
and **consumes** one of his one-time prekeys (OPKs); the response's `count`
reports how many remain. If fetching is unauthenticated and un-rate-limited,
Mallory drains Bob's OPK inventory so no new session can be started with Bob
until he republishes.

## Scenario

```
 Alice ─┐
        ├─ as3_server ⋯ (offline) Bob
Mallory ┘
```
Bob published and left; Alice and Mallory are both connected to the server.

## Files

- `attack1.cpp` — the malicious client (Step 2: single-connection drain loop).
- `Makefile` — `make` to build, `make clean` to remove the binary.

## Build & flags

```sh
make
```

| Flag             | Effect                                                   |
|------------------|----------------------------------------------------------|
| `--target U`     | whose OPKs to drain (default `bob`)                      |
| `--user U`       | username Mallory registers as (default `mallory`)       |
| `--no-register`  | skip `register` (fetch is unauthenticated — confirmed)  |
| `--count N`      | pull at most `N` OPKs (default: drain until empty)      |
| `--concurrent K` | open `K` sockets, fire one fetch each at once (A.3 race)|
| `--server ADDR`  | server address (default `127.0.0.1`)                    |
| `--port N`       | server port (default `9000`)                            |

## Roadmap (built in steps, each verified against the live lab)

### Step 1 — skeleton (done)
Connect, register as `mallory`, send **one** `fetch_bundle bob`, print `opk_id`
and remaining `count`. Confirmed: a fetch consumes one OPK, ids are handed out
sequentially (`1→5`), and **`--no-register` still fetches** — the endpoint is
unauthenticated.

### Step 2 — drain loop (current)
`drain()` fetches repeatedly over a **single connection** until the server
returns `err` (EMPTY), the reported `count` hits 0, or the `--count N` cap is
reached. Termination does **not** rely on `count` alone — the last successful
bundle omits `count` (shows `?(not reported)`), so an `err` is the authoritative
"empty" signal.

Test:
1. Reset so Bob has a full pool, then publish his bundle:
   ```sh
   docker compose down -v                  # clean reset
   docker compose up as3_server            # T1
   docker compose run --rm bob             # T2: publish bundle, then exit (offline)
   ```
2. Drain in one shot: `./attack1` (or `./attack1 --no-register`). Expect
   `5` OPKs pulled, then `pool exhausted` / `err: no one-time prekeys available`.
   Cross-check the server's `OPKs remaining: 4,3,2,1,0` then `DENIED` lines.
3. Cap test: reset, then `./attack1 --count 3` — pulls exactly 3, leaves 2.
4. Confirm the `opk_id`s walk down and never repeat within the run (A.4).

### Step 3 — concurrency + consequence probes (current)
Auth and rate-limit are already settled by Steps 1–2 (fetch works unregistered;
all 5 fetches + the denial land in the same server-log second). Two things left:

- **Concurrency (A.3) — code:** `./attack1 --concurrent K` opens `K` sockets,
  registers each as `mallory0..malloryK`, then releases all `K` fetches at the
  same instant (spin-flag barrier) and reports any `opk_id` handed to more than
  one request. A duplicate means allocation is **not atomic** — two initiators
  could share one "one-time" prekey. Reset Bob to 5 OPKs, run `--concurrent 5`
  (or more); **re-run several times** — a race may only surface intermittently.
- **Consequence — manual, the real impact:** after draining Bob (`./attack1`),
  bring up real **Alice** and have her start a session with offline Bob:
  ```sh
  docker compose down -v && docker compose up as3_server   # T1
  docker compose run --rm bob          # T2: publish, then exit (offline)
  cd attack1 && ./attack1              # T3: drain all 5
  docker compose run --rm alice        # T4: 1) message user -> bob
  ```
  Record which happens: Alice is **blocked** (DoS — can't start the session) or
  she **proceeds without an OPK** (silent downgrade — the session loses the
  one-time-prekey contribution to forward/break-in secrecy). Either way is the
  security consequence; note the exact client/server messages.

### Step 4 — fix + report
Write up A/B/C in the top-level `Report.md §4`; propose a fix (authenticate and
rate-limit `fetch_bundle`; consume an OPK at message-receipt rather than at
fetch; keep a signed-prekey fallback so exhaustion degrades gracefully).

## Open questions to answer (spec Part A)

1. How OPKs are generated, stored, published, and replenished.
2. Does `fetch_bundle` consume an OPK, or does consumption happen at another
   stage (e.g. first message)?
3. Can the same OPK be allocated to multiple concurrent requests?
4. What happens when no OPKs remain?
