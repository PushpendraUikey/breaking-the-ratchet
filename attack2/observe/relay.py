#!/usr/bin/env python3
"""
Phase-0 passive logging relay for Attack 2 (no attack, no crypto).

Sits between the lab clients and the REAL server and forwards every byte
unchanged, while writing each complete newline-JSON frame (both directions) to
stdout so it can be decoded with inspect.py.

    LISTEN  on  0.0.0.0:<listen_port>   <- clients connect here
    FORWARD to  <server_host>:<server_port>   (the genuine as3_server)

Usage:
    python3 relay.py [listen_port=9200] [server_host=127.0.0.1] [server_port=9000] \
        [--all] > cap.jsonl
    # direction markers go to stderr; raw JSON frames go to stdout (cap.jsonl)
    #
    # By default the capture omits the keepalive noise that clutters analysis:
    #   * `poll` requests, and
    #   * empty `frames` responses (polls that returned nothing).
    # These are still FORWARDED unchanged (a passive relay must forward all
    # bytes); they are only hidden from the log. Pass --all to log everything.

Point the clients at this relay (they run in Docker; reach the host via
host.docker.internal):
    docker compose run --rm bob   /client --server-addr host.docker.internal --port 9200
    docker compose run --rm alice /client --server-addr host.docker.internal --port 9200
"""
import sys
import json
import socket
import threading

_args = [a for a in sys.argv[1:] if not a.startswith("--")]
LOG_ALL = "--all" in sys.argv[1:]

LISTEN_PORT = int(_args[0]) if len(_args) > 0 else 9200
SERVER_HOST = _args[1] if len(_args) > 1 else "127.0.0.1"
SERVER_PORT = int(_args[2]) if len(_args) > 2 else 9000

_print_lock = threading.Lock()


def worth_logging(text):
    """Filter keepalive noise from the LOG only (bytes are forwarded regardless):
    drop `poll` requests and empty `frames` responses. --all keeps everything."""
    if LOG_ALL:
        return True
    try:
        o = json.loads(text)
    except ValueError:
        return True  # non-JSON: keep it so nothing is silently lost
    t = o.get("type")
    if t == "poll":
        return False
    if t == "frames" and not o.get("frames"):
        return False
    return True


def log_frame(direction, line):
    """Raw JSON frame -> stdout (capture); human marker -> stderr."""
    with _print_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
        preview = line if len(line) <= 120 else line[:117] + "..."
        sys.stderr.write(f"{direction} {preview}\n")
        sys.stderr.flush()


def pump(src, dst, direction):
    """Forward src->dst byte-for-byte; log each complete \\n-terminated line."""
    buf = b""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)          # forward unchanged (passive relay)
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode("utf-8", errors="replace").strip()
                if text and worth_logging(text):
                    log_frame(direction, text)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_client(client, addr):
    cid = f"{addr[1]}"   # client port, to tell bob/alice connections apart
    try:
        upstream = socket.create_connection((SERVER_HOST, SERVER_PORT))
    except OSError as e:
        sys.stderr.write(f"[relay] cannot reach server: {e}\n")
        client.close()
        return
    sys.stderr.write(f"[relay] client {cid} connected -> "
                     f"{SERVER_HOST}:{SERVER_PORT}\n")
    t1 = threading.Thread(target=pump, args=(client, upstream, f"C{cid}->S"),
                          daemon=True)
    t2 = threading.Thread(target=pump, args=(upstream, client, f"S->C{cid}"),
                          daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
    client.close(); upstream.close()
    sys.stderr.write(f"[relay] client {cid} closed\n")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(8)
    sys.stderr.write(f"[relay] listening on :{LISTEN_PORT}, forwarding to "
                     f"{SERVER_HOST}:{SERVER_PORT}"
                     f"{'  (logging ALL)' if LOG_ALL else '  (poll/empty-frames hidden)'}\n")
    try:
        while True:
            client, addr = srv.accept()
            threading.Thread(target=handle_client, args=(client, addr),
                             daemon=True).start()
    except KeyboardInterrupt:
        sys.stderr.write("\n[relay] shutting down\n")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
