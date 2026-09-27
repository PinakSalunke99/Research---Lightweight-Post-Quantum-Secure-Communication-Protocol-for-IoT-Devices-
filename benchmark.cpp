/*
    Paper-faithful protocol benchmark:
    "Lightweight Post-Quantum Secure Communication Protocol for IoT Devices
     Using Code-Based Cryptography"

    PURPOSE
    -------
    1. Implements the paper's protocol flow:
       - Registration
       - Mutual authentication
       - Password update
       - Session-key derivation
    2. Replaces SHA-512 with several selectable hash functions.
    3. Benchmarks each hash over multiple protocol runs.
    4. Reports timing, throughput, digest size, and derived session-key size.
    5. Sweeps several nonce/password/ID sizes.

    IMPORTANT CRYPTOGRAPHIC SCOPE
    ------------------------------
    The paper specifies ROLLO-II as the PKE layer but does not provide a
    complete ROLLO-II implementation. Therefore this SINGLE FILE deliberately
    separates the protocol from the PKE primitive.

    The "MockPKE" below is ONLY a reversible stand-in for Enc_PK/Dec_SK so
    that the protocol and hash benchmark can be executed. It is NOT ROLLO-II,
    is NOT post-quantum secure, and must NOT be used for real communication.

    To integrate real ROLLO-II later, replace MockPKE::encrypt/decrypt with
    the real ROLLO-II-128 implementation. The protocol and benchmark code
    below can remain unchanged.

    HASHES (OpenSSL EVP)
    --------------------
    - SHA-256
    - SHA-512       <-- paper baseline
    - SHA3-256
    - SHA3-512
    - BLAKE2s-256
    - BLAKE2b-512

    BUILD
    -----
    Linux/macOS:
        g++ -O3 -std=c++17 protocol_hash_benchmark.cpp \
            -lcrypto -o protocol_hash_benchmark

    Windows with MSYS2/MinGW + OpenSSL:
        g++ -O3 -std=c++17 protocol_hash_benchmark.cpp \
            -lcrypto -o protocol_hash_benchmark.exe

    RUN
    ---
        ./protocol_hash_benchmark

    Optional command-line arguments:
        --iterations N       authentication iterations per configuration
        --warmup N           warm-up authentication runs
        --csv FILE            additionally write CSV results
        --hash NAME           run only one hash
        --quick               smaller benchmark sweep

    Example:
        ./protocol_hash_benchmark --iterations 1000 --warmup 100
        ./protocol_hash_benchmark --hash SHA-512 --iterations 5000
        ./protocol_hash_benchmark --csv results.csv

    NOTE ABOUT THE PAPER'S XOR
    --------------------------
    The paper uses Pw XOR N2 and Pwn XOR ID_D. XOR requires equal-length
    byte strings. The paper does not define an ID_D padding/encoding rule.
    This implementation therefore makes ID_D exactly password-sized for each
    benchmark configuration, rather than inventing an undocumented encoding.
*/

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;
using Clock = std::chrono::steady_clock;

static Bytes random_bytes(size_t n) {
    Bytes out(n);
    if (n > 0 && RAND_bytes(out.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("OpenSSL RAND_bytes failed");
    return out;
}

static Bytes xor_bytes(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size())
        throw std::invalid_argument("XOR operands must have equal length");
    Bytes out(a.size());
    for (size_t i = 0; i < a.size(); ++i)
        out[i] = static_cast<unsigned char>(a[i] ^ b[i]);
    return out;
}

static bool secure_equal(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    return a.empty() ||
           CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

static void append_u32(Bytes& out, uint32_t x) {
    out.push_back(static_cast<unsigned char>((x >> 24) & 0xff));
    out.push_back(static_cast<unsigned char>((x >> 16) & 0xff));
    out.push_back(static_cast<unsigned char>((x >> 8) & 0xff));
    out.push_back(static_cast<unsigned char>(x & 0xff));
}

static Bytes encode_identity_nonce(const Bytes& id, const Bytes& nonce) {
    Bytes out;
    append_u32(out, static_cast<uint32_t>(id.size()));
    out.insert(out.end(), id.begin(), id.end());
    out.insert(out.end(), nonce.begin(), nonce.end());
    return out;
}

static std::pair<Bytes, Bytes> decode_identity_nonce(
    const Bytes& in, size_t nonce_size)
{
    if (in.size() < 4) throw std::runtime_error("Malformed PKE plaintext");
    uint32_t id_len =
        (static_cast<uint32_t>(in[0]) << 24) |
        (static_cast<uint32_t>(in[1]) << 16) |
        (static_cast<uint32_t>(in[2]) << 8) |
        static_cast<uint32_t>(in[3]);

    size_t expected = 4ULL + id_len + nonce_size;
    if (in.size() != expected)
        throw std::runtime_error("Malformed identity/nonce payload");

    Bytes id(in.begin() + 4, in.begin() + 4 + id_len);
    Bytes nonce(in.begin() + 4 + id_len, in.end());
    return {id, nonce};
}

/* ================================================================
   HASH ABSTRACTION
   ================================================================ */

enum class HashKind {
    SHA256,
    SHA512,
    SHA3_256,
    SHA3_512,
    BLAKE2S256,
    BLAKE2B512
};

struct HashInfo {
    HashKind kind;
    const char* name;
    size_t digest_size;
};

static const std::vector<HashInfo> ALL_HASHES = {
    {HashKind::SHA256,    "SHA-256",    32},
    {HashKind::SHA512,    "SHA-512",    64},
    {HashKind::SHA3_256,  "SHA3-256",   32},
    {HashKind::SHA3_512,  "SHA3-512",   64},
    {HashKind::BLAKE2S256,"BLAKE2s-256",32},
    {HashKind::BLAKE2B512,"BLAKE2b-512",64}
};

static const EVP_MD* openssl_md(HashKind kind) {
    switch (kind) {
        case HashKind::SHA256:     return EVP_sha256();
        case HashKind::SHA512:     return EVP_sha512();
        case HashKind::SHA3_256:   return EVP_sha3_256();
        case HashKind::SHA3_512:   return EVP_sha3_512();
        case HashKind::BLAKE2S256: return EVP_blake2s256();
        case HashKind::BLAKE2B512: return EVP_blake2b512();
    }
    throw std::runtime_error("Unknown hash");
}

static Bytes hash_data(HashKind kind, const Bytes& data) {
    const EVP_MD* md = openssl_md(kind);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    unsigned int out_len = EVP_MD_size(md);
    Bytes out(out_len);

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        (data.empty() ? true :
         EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) ||
        EVP_DigestFinal_ex(ctx, out.data(), &out_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("OpenSSL digest operation failed");
    }

    out.resize(out_len);
    EVP_MD_CTX_free(ctx);
    return out;
}

/*
   H(data) = selected hash.
   For the paper's SHA-512 baseline:
       H = SHA-512
       session key = 512 bits
*/
static Bytes H(HashKind kind, const Bytes& data) {
    return hash_data(kind, data);
}

/* ================================================================
   MOCK PKE BACKEND
   ================================================================ */

/*
   This is intentionally NOT ROLLO-II.

   It only supplies:
       Enc_PK(message)
       Dec_SK(ciphertext)

   so that the protocol's hash contribution can be benchmarked now.

   The "public" and "private" keys are represented by the same random
   symmetric key. AES-256-GCM is used internally only as a reversible
   transport simulation. It MUST NOT be described as ROLLO-II.
*/

class MockPKE {
public:
    struct KeyPair {
        Bytes public_key;
        Bytes private_key;
    };

    struct Config {
        size_t simulated_keygen_bytes = 32;
    };

    MockPKE() : cfg_{} {}
    explicit MockPKE(Config cfg) : cfg_(cfg) {}

    KeyPair keygen() const {
        Bytes k = random_bytes(cfg_.simulated_keygen_bytes);
        return {k, k};
    }

    Bytes encrypt(const Bytes& key, const Bytes& plaintext) const {
        /*
           We intentionally avoid an additional dependency on EVP AES in the
           benchmark. This is a deterministic reversible stream wrapper for
           protocol testing, not cryptography.

           The real ROLLO-II replacement must go here.
        */
        Bytes nonce = random_bytes(16);
        Bytes stream = keystream(key, nonce, plaintext.size());
        Bytes c(16 + plaintext.size());
        std::copy(nonce.begin(), nonce.end(), c.begin());
        for (size_t i = 0; i < plaintext.size(); ++i)
            c[16 + i] = plaintext[i] ^ stream[i];
        return c;
    }

    Bytes decrypt(const Bytes& key, const Bytes& ciphertext) const {
        if (ciphertext.size() < 16)
            throw std::runtime_error("Malformed mock ciphertext");

        Bytes nonce(ciphertext.begin(), ciphertext.begin() + 16);
        Bytes body(ciphertext.begin() + 16, ciphertext.end());
        Bytes stream = keystream(key, nonce, body.size());

        Bytes p(body.size());
        for (size_t i = 0; i < body.size(); ++i)
            p[i] = body[i] ^ stream[i];
        return p;
    }

private:
    Config cfg_;

    static Bytes keystream(
        const Bytes& key, const Bytes& nonce, size_t n)
    {
        Bytes out;
        out.reserve(n);

        uint32_t counter = 0;
        while (out.size() < n) {
            Bytes block = key;
            block.insert(block.end(), nonce.begin(), nonce.end());
            append_u32(block, counter++);
            Bytes h = hash_data(HashKind::SHA256, block);
            size_t take = std::min(h.size(), n - out.size());
            out.insert(out.end(), h.begin(), h.begin() + take);
        }
        return out;
    }
};

/* ================================================================
   PAPER PROTOCOL
   ================================================================ */

struct Device {
    Bytes id;
    Bytes public_key;
    Bytes private_key;
    Bytes password;
};

struct ServerRecord {
    Bytes password;
};

struct Server {
    Bytes public_key;
    Bytes private_key;
    std::map<std::string, ServerRecord> db;
};

struct ProtocolConfig {
    size_t nonce_size = 32;
    size_t password_size = 32;
    size_t id_size = 32;
};

struct ProtocolStats {
    uint64_t hash_calls = 0;
    uint64_t xor_calls = 0;
    uint64_t pke_encrypt_calls = 0;
    uint64_t pke_decrypt_calls = 0;
};

static std::string key_of(const Bytes& x) {
    return std::string(reinterpret_cast<const char*>(x.data()), x.size());
}

class PaperProtocol {
public:
    PaperProtocol(
        HashKind hash_kind,
        ProtocolConfig cfg,
        MockPKE& pke)
        : hash_kind_(hash_kind), cfg_(cfg), pke_(pke) {}

    Server create_server() {
        auto kp = pke_.keygen();
        return {kp.public_key, kp.private_key, {}};
    }

    Device create_device(const Bytes& id) {
        if (id.size() != cfg_.id_size)
            throw std::invalid_argument("Device ID size mismatch");
        auto kp = pke_.keygen();
        return {id, kp.public_key, kp.private_key, {}};
    }

    /*
       Algorithm 4 from the paper:
       Device Registration Phase Using ROLLO-II
    */
    void register_device(Device& device, Server& server, ProtocolStats* st = nullptr) {
        // Step 1
        Bytes n1 = random_bytes(cfg_.nonce_size);
        Bytes req_plain = encode_identity_nonce(device.id, n1);

        count_encrypt(st);
        Bytes req = pke_.encrypt(server.public_key, req_plain);

        // Step 2
        count_decrypt(st);
        Bytes recovered_req = pke_.decrypt(server.private_key, req);
        auto [id_d, recovered_n1] =
            decode_identity_nonce(recovered_req, cfg_.nonce_size);

        if (!secure_equal(id_d, device.id))
            throw std::runtime_error("Registration ID verification failed");

        Bytes pw = random_bytes(cfg_.password_size);

        Bytes server_response = recovered_n1;
        server_response.insert(
            server_response.end(), pw.begin(), pw.end());

        count_encrypt(st);
        Bytes et1 = pke_.encrypt(device.public_key, server_response);

        // Step 3
        count_decrypt(st);
        Bytes device_plain = pke_.decrypt(device.private_key, et1);

        if (device_plain.size() !=
            cfg_.nonce_size + cfg_.password_size)
            throw std::runtime_error("Malformed registration response");

        Bytes n1_prime(
            device_plain.begin(),
            device_plain.begin() + cfg_.nonce_size);

        Bytes pw_device(
            device_plain.begin() + cfg_.nonce_size,
            device_plain.end());

        if (!secure_equal(n1_prime, n1))
            throw std::runtime_error("Registration nonce mismatch");

        device.password = pw_device;

        // Step 4: rho1 = H(Pw XOR N1)
        Bytes pw_xor_n1 = xor_bytes(device.password, n1);
        count_xor(st);
        Bytes rho1 = H_counted(pw_xor_n1, st);

        Bytes expected = xor_bytes(pw, recovered_n1);
        count_xor(st);
        expected = H_counted(expected, st);

        if (!secure_equal(rho1, expected))
            throw std::runtime_error("Registration confirmation failed");

        server.db[key_of(id_d)] = {pw};
    }

    /*
       Algorithm 3 from the paper:
       Authentication Phase Using ROLLO-II
    */
    Bytes authenticate(
        Device& device,
        Server& server,
        ProtocolStats* st = nullptr)
    {
        if (device.password.empty())
            throw std::runtime_error("Device is not registered");

        auto it = server.db.find(key_of(device.id));
        if (it == server.db.end())
            throw std::runtime_error("Device not registered at server");

        // Step 1
        Bytes n2 = random_bytes(cfg_.nonce_size);
        Bytes payload = encode_identity_nonce(device.id, n2);

        count_encrypt(st);
        Bytes et2 = pke_.encrypt(server.public_key, payload);

        Bytes pw_xor_n2 = xor_bytes(device.password, n2);
        count_xor(st);
        Bytes rho2 = H_counted(pw_xor_n2, st);

        // Step 2
        count_decrypt(st);
        Bytes recovered = pke_.decrypt(server.private_key, et2);
        auto [id_d, recovered_n2] =
            decode_identity_nonce(recovered, cfg_.nonce_size);

        auto server_record = server.db.find(key_of(id_d));
        if (server_record == server.db.end())
            throw std::runtime_error("Unknown device");

        Bytes expected_rho2_input =
            xor_bytes(server_record->second.password, recovered_n2);
        count_xor(st);
        Bytes expected_rho2 =
            H_counted(expected_rho2_input, st);

        if (!secure_equal(rho2, expected_rho2))
            throw std::runtime_error("rho2 verification failed");

        // Pwn = Pw XOR N2
        Bytes pwn = xor_bytes(server_record->second.password, recovered_n2);
        count_xor(st);

        // rho3 = H(Pwn)
        Bytes rho3 = H_counted(pwn, st);

        // Step 3: device verifies rho3
        Bytes device_pwn = xor_bytes(device.password, n2);
        count_xor(st);

        Bytes expected_rho3 = H_counted(device_pwn, st);
        if (!secure_equal(rho3, expected_rho3))
            throw std::runtime_error("rho3 verification failed");

        // Update device password
        device.password = device_pwn;

        // rho4 = H(Pwn XOR ID_D)
        Bytes pwn_xor_id = xor_bytes(device.password, device.id);
        count_xor(st);
        Bytes rho4 = H_counted(pwn_xor_id, st);

        // SK = H(Pwn || ID_D)
        Bytes sk_input = device.password;
        sk_input.insert(
            sk_input.end(), device.id.begin(), device.id.end());
        Bytes sk_device = H_counted(sk_input, st);

        // Step 4 server verifies rho4
        Bytes server_rho4_input =
            xor_bytes(pwn, id_d);
        count_xor(st);

        Bytes expected_rho4 =
            H_counted(server_rho4_input, st);

        if (!secure_equal(rho4, expected_rho4))
            throw std::runtime_error("rho4 verification failed");

        // Server updates password
        server_record->second.password = pwn;

        // Server derives same SK
        Bytes server_sk_input = pwn;
        server_sk_input.insert(
            server_sk_input.end(), id_d.begin(), id_d.end());
        Bytes sk_server = H_counted(server_sk_input, st);

        if (!secure_equal(sk_device, sk_server))
            throw std::runtime_error("Session key mismatch");

        return sk_device;
    }

private:
    HashKind hash_kind_;
    ProtocolConfig cfg_;
    MockPKE& pke_;

    Bytes H_counted(const Bytes& x, ProtocolStats* st) {
        if (st) ++st->hash_calls;
        return H(hash_kind_, x);
    }

    static void count_encrypt(ProtocolStats* st) {
        if (st) ++st->pke_encrypt_calls;
    }

    static void count_decrypt(ProtocolStats* st) {
        if (st) ++st->pke_decrypt_calls;
    }

    static void count_xor(ProtocolStats* st) {
        if (st) ++st->xor_calls;
    }
};

/* ================================================================
   BENCHMARKING
   ================================================================ */

struct BenchmarkResult {
    std::string hash_name;
    size_t digest_bytes;
    size_t nonce_bytes;
    size_t password_bytes;
    size_t id_bytes;
    int iterations;

    double registration_us;
    double authentication_us;
    double authentication_hash_us;
    double authentication_xor_us;
    double authentication_hash_only_us;

    double auth_throughput_per_sec;

    uint64_t hash_calls_per_auth;
    uint64_t xor_calls_per_auth;
    uint64_t pke_enc_per_auth;
    uint64_t pke_dec_per_auth;
};

static double elapsed_us(
    const Clock::time_point& a,
    const Clock::time_point& b)
{
    return std::chrono::duration<double, std::micro>(b - a).count();
}

static Bytes make_id(size_t n, uint8_t seed) {
    Bytes id(n);
    for (size_t i = 0; i < n; ++i)
        id[i] = static_cast<unsigned char>(seed + i);
    return id;
}

static BenchmarkResult benchmark_configuration(
    const HashInfo& hash,
    const ProtocolConfig& cfg,
    int iterations,
    int warmup,
    MockPKE& pke)
{
    BenchmarkResult r{};
    r.hash_name = hash.name;
    r.digest_bytes = hash.digest_size;
    r.nonce_bytes = cfg.nonce_size;
    r.password_bytes = cfg.password_size;
    r.id_bytes = cfg.id_size;
    r.iterations = iterations;

    // Registration is timed once per benchmark configuration.
    {
        PaperProtocol protocol(hash.kind, cfg, pke);
        Server server = protocol.create_server();
        Device device = protocol.create_device(make_id(cfg.id_size, 7));

        auto t0 = Clock::now();
        protocol.register_device(device, server);
        auto t1 = Clock::now();

        r.registration_us = elapsed_us(t0, t1);
    }

    // Warm-up
    {
        PaperProtocol protocol(hash.kind, cfg, pke);
        Server server = protocol.create_server();
        Device device = protocol.create_device(make_id(cfg.id_size, 13));
        protocol.register_device(device, server);

        for (int i = 0; i < warmup; ++i)
            protocol.authenticate(device, server);
    }

    // Main authentication benchmark.
    {
        PaperProtocol protocol(hash.kind, cfg, pke);
        Server server = protocol.create_server();
        Device device = protocol.create_device(make_id(cfg.id_size, 19));
        protocol.register_device(device, server);

        ProtocolStats stats{};

        auto t0 = Clock::now();
        for (int i = 0; i < iterations; ++i)
            protocol.authenticate(device, server, &stats);
        auto t1 = Clock::now();

        double total_us = elapsed_us(t0, t1);

        r.authentication_us = total_us / iterations;
        r.auth_throughput_per_sec =
            1'000'000.0 / r.authentication_us;

        r.hash_calls_per_auth =
            stats.hash_calls / static_cast<uint64_t>(iterations);
        r.xor_calls_per_auth =
            stats.xor_calls / static_cast<uint64_t>(iterations);
        r.pke_enc_per_auth =
            stats.pke_encrypt_calls / static_cast<uint64_t>(iterations);
        r.pke_dec_per_auth =
            stats.pke_decrypt_calls / static_cast<uint64_t>(iterations);
    }

    /*
       Isolate hash/XOR cost from PKE by directly reproducing the protocol's
       hash inputs. This is especially useful because the actual ROLLO-II
       implementation is not included in the paper.
    */
    {
        Bytes pw = random_bytes(cfg.password_size);
        Bytes n2 = random_bytes(cfg.nonce_size);
        Bytes id = make_id(cfg.id_size, 31);

        if (pw.size() != n2.size() || pw.size() != id.size())
            throw std::runtime_error(
                "Benchmark configuration violates paper XOR size requirement");

        std::vector<Bytes> inputs;
        inputs.reserve(5);

        for (int i = 0; i < 5; ++i) {
            Bytes x = xor_bytes(pw, n2);
            if (i == 1) x = pw;
            if (i == 2) x = xor_bytes(pw, id);
            if (i == 3) {
                x = pw;
                x.insert(x.end(), id.begin(), id.end());
            }
            if (i == 4) x = xor_bytes(xor_bytes(pw, n2), id);
            inputs.push_back(std::move(x));
        }

        volatile unsigned char sink = 0;

        auto h0 = Clock::now();
        for (int i = 0; i < iterations; ++i) {
            for (const auto& x : inputs) {
                Bytes d = H(hash.kind, x);
                sink ^= d[i % d.size()];
            }
        }
        auto h1 = Clock::now();

        r.authentication_hash_only_us =
            elapsed_us(h0, h1) / iterations;

        // Prevent an optimizer from eliminating the benchmark.
        if (sink == 0xFF)
            std::cerr << "";
    }

    return r;
}

static void print_header() {
    std::cout << "\n"
              << "==============================================================\n"
              << " PAPER PROTOCOL HASH BENCHMARK\n"
              << "==============================================================\n"
              << "Protocol: ROLLO-II based IoT protocol from the paper\n"
              << "Baseline hash: SHA-512\n"
              << "PKE: MOCK ONLY (replace with real ROLLO-II later)\n"
              << "==============================================================\n\n";
}

static void print_result(const BenchmarkResult& r) {
    std::cout << std::left
              << std::setw(13) << r.hash_name
              << std::right
              << std::setw(7) << r.digest_bytes
              << std::setw(8) << r.nonce_bytes
              << std::setw(8) << r.authentication_us
              << std::setw(10) << r.authentication_hash_only_us
              << std::setw(12) << r.auth_throughput_per_sec
              << "\n";
}

static void print_csv_header(std::ofstream& f) {
    f << "hash,digest_bytes,nonce_bytes,password_bytes,id_bytes,"
         "iterations,registration_us,authentication_us,"
         "authentication_hash_only_us,throughput_auth_per_sec,"
         "hash_calls_per_auth,xor_calls_per_auth,"
         "pke_encrypt_calls_per_auth,pke_decrypt_calls_per_auth\n";
}

static void print_csv(std::ofstream& f, const BenchmarkResult& r) {
    f << r.hash_name << ','
      << r.digest_bytes << ','
      << r.nonce_bytes << ','
      << r.password_bytes << ','
      << r.id_bytes << ','
      << r.iterations << ','
      << r.registration_us << ','
      << r.authentication_us << ','
      << r.authentication_hash_only_us << ','
      << r.auth_throughput_per_sec << ','
      << r.hash_calls_per_auth << ','
      << r.xor_calls_per_auth << ','
      << r.pke_enc_per_auth << ','
      << r.pke_dec_per_auth << '\n';
}

struct Args {
    int iterations = 2000;
    int warmup = 100;
    bool quick = false;
    std::string hash_filter;
    std::string csv_file;
};

static Args parse_args(int argc, char** argv) {
    Args a;

    for (int i = 1; i < argc; ++i) {
        std::string x = argv[i];

        auto need_value = [&](const char* flag) -> std::string {
            if (i + 1 >= argc)
                throw std::invalid_argument(
                    std::string("Missing value after ") + flag);
            return argv[++i];
        };

        if (x == "--iterations") {
            a.iterations = std::stoi(need_value("--iterations"));
        } else if (x == "--warmup") {
            a.warmup = std::stoi(need_value("--warmup"));
        } else if (x == "--hash") {
            a.hash_filter = need_value("--hash");
        } else if (x == "--csv") {
            a.csv_file = need_value("--csv");
        } else if (x == "--quick") {
            a.quick = true;
        } else if (x == "--help") {
            std::cout
                << "Usage:\n"
                << "  --iterations N   authentication repetitions\n"
                << "  --warmup N       warm-up repetitions\n"
                << "  --hash NAME      one hash only\n"
                << "  --csv FILE       save CSV\n"
                << "  --quick          smaller parameter sweep\n";
            std::exit(0);
        } else {
            throw std::invalid_argument("Unknown argument: " + x);
        }
    }

    if (a.iterations <= 0 || a.warmup < 0)
        throw std::invalid_argument("Invalid benchmark counts");

    return a;
}

int main(int argc, char** argv) {
    try {
        Args args = parse_args(argc, argv);
        print_header();

        std::vector<HashInfo> hashes;

        if (args.hash_filter.empty()) {
            hashes = ALL_HASHES;
        } else {
            for (const auto& h : ALL_HASHES) {
                if (args.hash_filter == h.name)
                    hashes.push_back(h);
            }
            if (hashes.empty())
                throw std::invalid_argument(
                    "Unknown hash. Try SHA-256, SHA-512, SHA3-256, "
                    "SHA3-512, BLAKE2s-256, or BLAKE2b-512.");
        }

        std::vector<size_t> sizes =
            args.quick
            ? std::vector<size_t>{16, 32, 64}
            : std::vector<size_t>{16, 32, 64, 128, 256};

        MockPKE pke;
        std::vector<BenchmarkResult> results;

        std::cout
            << std::left
            << std::setw(13) << "Hash"
            << std::right
            << std::setw(7) << "Digest"
            << std::setw(8) << "Size"
            << std::setw(12) << "Auth us"
            << std::setw(14) << "Hash-only us"
            << std::setw(15) << "Auth/sec"
            << "\n";

        std::cout << std::string(69, '-') << "\n";

        /*
           The paper's protocol requires equal-length operands for:
               Pw XOR N2
               Pwn XOR ID_D

           Therefore nonce, password, and ID are kept equal for each
           parameter point. This is a parameter sweep, not a modification
           of the paper's mathematical protocol.
        */
        for (size_t n : sizes) {
            ProtocolConfig cfg;
            cfg.nonce_size = n;
            cfg.password_size = n;
            cfg.id_size = n;

            for (const auto& h : hashes) {
                BenchmarkResult r =
                    benchmark_configuration(
                        h, cfg, args.iterations, args.warmup, pke);

                results.push_back(r);
                print_result(r);
            }
        }

        if (!args.csv_file.empty()) {
            std::ofstream f(args.csv_file);
            if (!f)
                throw std::runtime_error(
                    "Could not open CSV output file");

            print_csv_header(f);
            for (const auto& r : results)
                print_csv(f, r);

            std::cout << "\nCSV written to: "
                      << args.csv_file << "\n";
        }

        /*
           Print the paper baseline separately.
        */
        auto sha512_it = std::find_if(
            results.begin(), results.end(),
            [](const BenchmarkResult& r) {
                return r.hash_name == "SHA-512" &&
                       r.nonce_bytes == 32;
            });

        if (sha512_it != results.end()) {
            std::cout
                << "\nPaper baseline point (SHA-512, 32-byte "
                   "nonce/password/ID):\n"
                << "  Authentication: "
                << sha512_it->authentication_us << " us/auth\n"
                << "  Hash-only:      "
                << sha512_it->authentication_hash_only_us
                << " us/auth\n"
                << "  Throughput:     "
                << sha512_it->auth_throughput_per_sec
                << " auth/s\n"
                << "  Digest/session-key size: "
                << sha512_it->digest_bytes * 8
                << " bits\n";
        }

        std::cout
            << "\nInterpretation:\n"
            << "  'Auth us' includes the protocol plus the MOCK PKE layer.\n"
            << "  'Hash-only us' isolates the hash portion using the same\n"
            << "  protocol-style inputs. Use this column to compare hashes\n"
            << "  fairly before integrating a real ROLLO-II implementation.\n"
            << "\nWARNING: MockPKE is not ROLLO-II and the resulting timings must\n"
            << "not be reported as ROLLO-II performance.\n";

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "\nERROR: " << e.what() << "\n";
        return 1;
    }
}
