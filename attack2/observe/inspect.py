#!/usr/bin/env python3
"""
Phase-0 observation helper for Attack 2 (malicious-server MITM).

Reads captured AS3 wire frames (newline-delimited JSON) and decodes the
security-relevant fields so we can answer the trust-model questions and lock
down the exact bundle / header layout the malicious server must reproduce.

Two input modes:

  # (A) feed it the readable JSON lines directly (e.g. from a logging relay):
  python3 inspect.py session.jsonl

  # (B) feed it tshark's raw TCP payload hex (spec-suggested capture):
  tshark -i any -f "tcp port 9000" -T fields -e tcp.payload \
      | python3 inspect.py --hex

It prints, per frame: the envelope type, and for `bundle` / `frames` the
base64-decoded field sizes (so we can confirm X25519=32, Ed25519=32, etc.) and
the literal header JSON (our best read on how `serialize(header)` is encoded).
"""
import sys
import json
import base64


def b64len(s):
    """Return the decoded byte length of a base64 string, or a marker."""
    if s is None:
        return "absent"
    if s == "":
        return "empty"
    try:
        return f"{len(base64.b64decode(s))} bytes"
    except Exception:
        return "not-base64"


def show_bundle(b):
    print("  bundle for user:", b.get("user"))
    for k in ("ik_sig", "ik_dh", "spk", "spk_sig", "opk"):
        print(f"    {k:8} = {b64len(b.get(k))}")
    print(f"    opk_id   = {b.get('opk_id')}")


def show_frame(fr, idx):
    hdr = fr.get("header", {})
    print(f"  frame[{idx}] {fr.get('from')} -> {fr.get('to')}")
    # The literal header object as transmitted: strong hint for serialize().
    print(f"    header JSON = {json.dumps(hdr, separators=(',', ':'))}")
    print(f"    dh={b64len(hdr.get('dh'))}  pn={hdr.get('pn')}  n={hdr.get('n')}")
    init = hdr.get("init")
    if init is not None:
        print("    init block PRESENT (first message of session):")
        for k in ("ik_sig", "ik_dh", "ek"):
            print(f"      {k:7} = {b64len(init.get(k))}")
        print(f"      opk_id = {init.get('opk_id')}")
    print(f"    ct = {b64len(fr.get('ct'))}")


def handle(obj):
    t = obj.get("type", "?")
    print(f"[{t}]", {k: obj.get(k) for k in ("user", "ok", "err", "count")
                     if obj.get(k) is not None})
    if obj.get("bundle"):
        show_bundle(obj["bundle"])
    if t == "frames" and isinstance(obj.get("frames"), list):
        for i, fr in enumerate(obj["frames"]):
            show_frame(fr, i)
    if obj.get("frame"):
        show_frame(obj["frame"], 0)


def iter_json_lines(raw):
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            # Not a complete JSON line (fragment) — skip quietly.
            continue


def main():
    args = sys.argv[1:]
    hexmode = "--hex" in args
    paths = [a for a in args if not a.startswith("--")]

    if hexmode:
        # Each stdin token is a hex blob of one TCP payload; concatenate then split.
        blob = bytearray()
        for tok in sys.stdin.read().split():
            try:
                blob += bytes.fromhex(tok)
            except ValueError:
                pass
        raw = blob.decode("utf-8", errors="replace")
    elif paths:
        raw = open(paths[0], "r", encoding="utf-8", errors="replace").read()
    else:
        raw = sys.stdin.read()

    n = 0
    for obj in iter_json_lines(raw):
        handle(obj)
        n += 1
    print(f"\n-- {n} frame(s) parsed --", file=sys.stderr)


if __name__ == "__main__":
    main()
