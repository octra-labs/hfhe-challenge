#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"

#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace pvac;

static constexpr std::array<uint8_t, 16> BUNDLE_MAGIC = {
    'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'
};

struct Meta {
    std::string dom;
    uint64_t seed_ztag;
    std::string nonce_lo_hex;
    std::string nonce_hi_hex;
    std::string public_T_hex;
};

struct Target {
    uint64_t seed_ztag;
    std::string nonce_lo_hex;
    std::string nonce_hi_hex;
    std::string public_T_hex;
};

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("open " + path);
    in.seekg(0, std::ios::end);
    size_t n = static_cast<size_t>(in.tellg());
    in.seekg(0);
    std::vector<uint8_t> out(n);
    if (n) in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(n));
    return out;
}

static std::string read_first_line(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("open " + path);
    std::string line;
    std::getline(in, line);
    return line;
}

static uint64_t take_u64(const std::vector<uint8_t>& in, size_t& pos) {
    if (pos + 8 > in.size()) throw std::runtime_error("truncated bundle");
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(in[pos++]) << (8 * i);
    return v;
}

static std::vector<Cipher> load_bundle(const std::string& path) {
    auto in = read_file(path);
    if (in.size() < BUNDLE_MAGIC.size() ||
        !std::equal(BUNDLE_MAGIC.begin(), BUNDLE_MAGIC.end(), in.begin()))
        throw std::runtime_error("bad bundle magic");

    size_t pos = BUNDLE_MAGIC.size();
    uint64_t count = take_u64(in, pos);
    if (count == 0 || count > 1024) throw std::runtime_error("bad bundle count");

    std::vector<Cipher> out;
    out.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t n = take_u64(in, pos);
        if (n == 0 || n > in.size() - pos) throw std::runtime_error("bad cipher length");
        out.push_back(pvac_ser::deserialize_cipher(in.data() + pos, static_cast<size_t>(n)));
        pos += static_cast<size_t>(n);
    }
    if (pos != in.size()) throw std::runtime_error("trailing bundle bytes");
    return out;
}

static std::string json_string(const std::string& line, const std::string& key) {
    std::string pat = "\"" + key + "\":\"";
    size_t p = line.find(pat);
    if (p == std::string::npos) throw std::runtime_error("missing key " + key);
    p += pat.size();
    size_t q = line.find('"', p);
    if (q == std::string::npos) throw std::runtime_error("bad string " + key);
    return line.substr(p, q - p);
}

static uint64_t json_u64(const std::string& line, const std::string& key) {
    std::string pat = "\"" + key + "\":";
    size_t p = line.find(pat);
    if (p == std::string::npos) throw std::runtime_error("missing key " + key);
    p += pat.size();
    size_t q = p;
    while (q < line.size() && line[q] >= '0' && line[q] <= '9') ++q;
    return std::stoull(line.substr(p, q - p));
}

static Meta parse_meta(const std::string& line) {
    Meta m;
    m.dom = json_string(line, "dom");
    m.seed_ztag = json_u64(line, "seed_ztag");
    m.nonce_lo_hex = json_string(line, "nonce_lo_hex");
    m.nonce_hi_hex = json_string(line, "nonce_hi_hex");
    m.public_T_hex = json_string(line, "public_T_hex");
    return m;
}

static std::string fp_hex(const Fp& x) {
    std::ostringstream out;
    out << std::hex << std::setfill('0')
        << std::setw(16) << (x.hi & MASK63)
        << std::setw(16) << x.lo;
    return out.str();
}

static std::string u64_hex(uint64_t x) {
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(16) << x;
    return out.str();
}

static Fp public_layer_aggregate(const PubKey& pk, const Cipher& c, uint32_t layer_id, size_t slot) {
    Fp acc = fp_from_u64(0);
    for (const auto& e : c.E) {
        if (e.layer_id != layer_id) continue;
        if (slot >= e.w.size()) throw std::runtime_error("edge slot missing");
        if (e.idx >= pk.powg_B.size()) throw std::runtime_error("edge index rejected");
        Fp term = fp_mul(e.w[slot], pk.powg_B[e.idx]);
        acc = sgn_val(e.ch) > 0 ? fp_add(acc, term) : fp_sub(acc, term);
    }
    return acc;
}

static std::vector<Target> collect_targets(const PubKey& pk, const std::vector<Cipher>& cts) {
    std::vector<Target> out;
    for (const auto& c : cts) {
        for (size_t lid = 0; lid < c.L.size(); ++lid) {
            const Layer& layer = c.L[lid];
            if (layer.rule != RRule::BASE) continue;
            for (size_t slot = 0; slot < c.slots; ++slot) {
                Fp t = public_layer_aggregate(pk, c, static_cast<uint32_t>(lid), slot);
                out.push_back(Target{
                    layer.seed.ztag,
                    u64_hex(layer.seed.nonce.lo),
                    u64_hex(layer.seed.nonce.hi),
                    fp_hex(t)
                });
            }
        }
    }
    return out;
}

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage = verify_lpn_sample_binding <pk.bin> <secret.ct> <sample.jsonl>\n";
        return 2;
    }

    try {
        auto pk_blob = read_file(argv[1]);
        PubKey pk = pvac_ser::deserialize_pubkey(pk_blob.data(), pk_blob.size());
        auto cts = load_bundle(argv[2]);
        Meta sample = parse_meta(read_first_line(argv[3]));

        if (sample.dom != "pvac.prf.r.1")
            throw std::runtime_error("unexpected domain");

        bool matched = false;
        for (const auto& target : collect_targets(pk, cts)) {
            matched =
                target.seed_ztag == sample.seed_ztag &&
                target.nonce_lo_hex == sample.nonce_lo_hex &&
                target.nonce_hi_hex == sample.nonce_hi_hex &&
                target.public_T_hex == sample.public_T_hex;
            if (matched) break;
        }

        std::cout << "binding = " << (matched ? 1 : 0) << "\n";
        return matched ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "error = " << e.what() << "\n";
        return 1;
    }
}