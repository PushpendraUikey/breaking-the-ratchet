// attack0.cpp — Message-counter manipulation (MITM between server and Bob)
//
// Role: Mallory, a man-in-the-middle on the wire between as3_server and Bob.
// Idea: intercept a frame addressed to Bob, inflate the header counter (n / pn)
// to open a large skip gap, and forward it. Observe how Bob's client processes
// the gap (skipped-key derivation + storage) before the AEAD check runs.
//
// This is a skeleton: fill in the TODOs once the wire behaviour is confirmed
// from packet captures and client logs.
//
// Build:  make
// Run:    ./attack0   (see README.md in this folder for setup)

#include <cstdio>
#include <cstdlib>
#include <string>

// ---------------------------------------------------------------------------
// Config — adjust to the lab environment.
// ---------------------------------------------------------------------------
namespace cfg {
    // Where Mallory listens for Bob, and where it forwards to the real server.
    // TODO: confirm addresses/ports once the MITM position is set up.
    const char* LISTEN_ADDR  = "0.0.0.0";
    const int   LISTEN_PORT   = 9200;      // Bob connects here instead of the server
    const char* SERVER_ADDR   = "as3_server";
    const int   SERVER_PORT    = 9000;     // real server
}

// ---------------------------------------------------------------------------
// Step 1 — relay a TCP connection between Bob and the server (newline-JSON).
// TODO: accept Bob's connection, dial the real server, pump bytes both ways,
//       splitting on '\n' so each line is one JSON frame we can inspect.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Step 2 — recognise a frame destined for Bob.
// A frame looks like: {"type":"send","frame":{"from":...,"to":"bob","header":{...},"ct":...}}
// TODO: parse the line as JSON; check type == "send" and frame.to == "bob".
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Step 3 — tamper with the counter.
// TODO: set header.n (and/or header.pn) to current + GAP, re-serialise, forward.
//       Start small, then increase GAP to probe the receiver's limit.
// ---------------------------------------------------------------------------
static const long GAP = 1000;  // counter inflation; sweep this in measurements

int main() {
    std::printf("[attack0] MITM counter-manipulation PoC (skeleton)\n");
    std::printf("[attack0] listen %s:%d  ->  server %s:%d  gap=%ld\n",
                cfg::LISTEN_ADDR, cfg::LISTEN_PORT,
                cfg::SERVER_ADDR, cfg::SERVER_PORT, GAP);
    // TODO: implement steps 1-3.
    return 0;
}
