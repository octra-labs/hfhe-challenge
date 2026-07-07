#include <pvac/pvac.hpp>
#include <pvac/utils/text.hpp>
#include "pvac_artifact_serialize.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <vector>
#include <sys/stat.h>

namespace fs = std::filesystem;
using namespace pvac;

namespace {
constexpr std::array<uint8_t, 16> BUNDLE_MAGIC = {
    'O','C','T','R','A','-','H','F','H','E','-','S','E','E','D','1'
};

void wipe(std::string& s) {
    volatile char* p = s.empty() ? nullptr : &s[0];
    for (size_t i = 0; i < s.size(); ++i) p[i] = 0;
    s.clear();
    s.shrink_to_fit();
}

std::string read_secret(const char* prompt) {
    if (!isatty(STDIN_FILENO)) throw std::runtime_error("stdin must be a terminal");
    std::cerr << prompt;
    termios oldt{};
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) throw std::runtime_error("tcgetattr failed");
    termios newt = oldt;
    newt.c_lflag &= static_cast<tcflag_t>(~ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) throw std::runtime_error("cannot disable echo");
    std::string s;
    std::getline(std::cin, s);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cerr << "\n";
    return s;
}

void write_file(const fs::path& path, const std::vector<uint8_t>& data, mode_t mode) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot open " + path.string());
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!out) throw std::runtime_error("cannot write " + path.string());
    out.close();
    if (::chmod(path.c_str(), mode) != 0) throw std::runtime_error("chmod failed for " + path.string());
}

std::vector<uint8_t> read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + path.string());
    in.seekg(0, std::ios::end);
    const auto n = in.tellg();
    if (n < 0) throw std::runtime_error("cannot size " + path.string());
    if (n > static_cast<std::streamoff>(1ULL << 32)) throw std::runtime_error("file too large: " + path.string());
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(static_cast<size_t>(n));
    if (!data.empty()) in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(n));
    if (!in) throw std::runtime_error("cannot read " + path.string());
    return data;
}

void append_u64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

uint64_t take_u64(const std::vector<uint8_t>& in, size_t& pos) {
    if (pos + 8 > in.size()) throw std::runtime_error("truncated seed.ct");
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(in[pos++]) << (8 * i);
    return v;
}

std::vector<uint8_t> serialize_bundle(const std::vector<Cipher>& cts) {
    std::vector<uint8_t> out(BUNDLE_MAGIC.begin(), BUNDLE_MAGIC.end());
    append_u64(out, cts.size());
    for (const auto& ct : cts) {
        auto blob = pvac_ser::serialize_cipher(ct);
        append_u64(out, blob.size());
        out.insert(out.end(), blob.begin(), blob.end());
    }
    return out;
}

std::vector<Cipher> deserialize_bundle(const std::vector<uint8_t>& in) {
    if (in.size() < BUNDLE_MAGIC.size() ||
        !std::equal(BUNDLE_MAGIC.begin(), BUNDLE_MAGIC.end(), in.begin()))
        throw std::runtime_error("bad seed.ct magic");
    size_t pos = BUNDLE_MAGIC.size();
    const uint64_t count = take_u64(in, pos);
    if (count == 0 || count > 1024) throw std::runtime_error("invalid cipher count");
    std::vector<Cipher> cts;
    cts.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        const uint64_t n = take_u64(in, pos);
        if (n == 0 || n > in.size() - pos) throw std::runtime_error("invalid cipher length");
        cts.push_back(pvac_ser::deserialize_cipher(in.data() + pos, static_cast<size_t>(n)));
        pos += static_cast<size_t>(n);
    }
    if (pos != in.size()) throw std::runtime_error("trailing bytes in seed.ct");
    return cts;
}

void write_params(const Params& p, size_t plaintext_bytes, size_t cipher_objects, const fs::path& path) {
    std::ofstream o(path, std::ios::trunc);
    if (!o) throw std::runtime_error("cannot open " + path.string());
    o << "{\n"
      << "  \"format\": \"octra-hfhe-seed-challenge-v1\",\n"
      << "  \"text_encoding\": \"length-cipher-plus-15-byte-blocks\",\n"
      << "  \"pubkey_encoding\": \"pvac-v2-compressed\",\n"
      << "  \"cipher_encoding\": \"pvac-v2-length-prefixed-bundle\",\n"
      << "  \"plaintext_bytes\": " << plaintext_bytes << ",\n"
      << "  \"cipher_objects\": " << cipher_objects << ",\n"
      << "  \"B\": " << p.B << ",\n"
      << "  \"m_bits\": " << p.m_bits << ",\n"
      << "  \"n_bits\": " << p.n_bits << ",\n"
      << "  \"h_col_wt\": " << p.h_col_wt << ",\n"
      << "  \"x_col_wt\": " << p.x_col_wt << ",\n"
      << "  \"err_wt\": " << p.err_wt << ",\n"
      << "  \"noise_entropy_bits\": " << p.noise_entropy_bits << ",\n"
      << "  \"tuple2_fraction\": " << p.tuple2_fraction << ",\n"
      << "  \"depth_slope_bits\": " << p.depth_slope_bits << ",\n"
      << "  \"edge_budget\": " << p.edge_budget << ",\n"
      << "  \"lpn_n\": " << p.lpn_n << ",\n"
      << "  \"lpn_t\": " << p.lpn_t << ",\n"
      << "  \"lpn_tau_num\": " << p.lpn_tau_num << ",\n"
      << "  \"lpn_tau_den\": " << p.lpn_tau_den << "\n"
      << "}\n";
    o.close();
    if (::chmod(path.c_str(), 0644) != 0) throw std::runtime_error("chmod failed for params.json");
}

void generate() {
    if (fs::exists("challenge_public") || fs::exists("challenge_private"))
        throw std::runtime_error("challenge_public or challenge_private already exists; refusing to overwrite");

    std::string seed1 = read_secret("mnemonic = ");
    std::string seed2 = read_secret("mnemonic_confirm = ");
    if (seed1.empty() || seed1 != seed2) {
        wipe(seed1); wipe(seed2);
        throw std::runtime_error("mnemonics do not match");
    }

    fs::create_directory("challenge_public");
    fs::create_directory("challenge_private");
    ::chmod("challenge_public", 0755);
    ::chmod("challenge_private", 0700);

    Params prm;
    prm.noise_entropy_bits = 128.0;
    PubKey pk;
    SecKey sk;
    std::cout << "event = keygen\n";
    keygen(prm, pk, sk);
    std::cout << "event = encrypt bytes = " << seed1.size() << "\n";
    auto cts = enc_text(pk, sk, seed1);

    auto pk_blob = pvac_ser::serialize_pubkey(pk, true);
    auto sk_blob = pvac_ser::serialize_seckey(sk);
    auto ct_blob = serialize_bundle(cts);

    write_file("challenge_public/pk.bin", pk_blob, 0644);
    write_file("challenge_public/seed.ct", ct_blob, 0644);
    write_file("challenge_private/sk.bin", sk_blob, 0600);
    write_params(prm, seed1.size(), cts.size(), "challenge_public/params.json");

    auto pk2_blob = read_file("challenge_public/pk.bin");
    auto sk2_blob = read_file("challenge_private/sk.bin");
    auto ct2_blob = read_file("challenge_public/seed.ct");
    auto pk2 = pvac_ser::deserialize_pubkey(pk2_blob.data(), pk2_blob.size());
    auto sk2 = pvac_ser::deserialize_seckey(sk2_blob.data(), sk2_blob.size());
    auto cts2 = deserialize_bundle(ct2_blob);
    auto recovered = dec_text(pk2, sk2, cts2);
    const bool ok = recovered == seed1;
    wipe(recovered); wipe(seed1); wipe(seed2);
    if (!ok) throw std::runtime_error("disk round-trip verification failed");

    std::cout << "ok = disk_roundtrip\n"
              << "cipher_objects = " << cts.size() << "\n"
              << "public_path = challenge_public\n"
              << "secret_path = challenge_private/sk.bin\n";
}

void verify() {
    auto pk_blob = read_file("challenge_public/pk.bin");
    auto sk_blob = read_file("challenge_private/sk.bin");
    auto ct_blob = read_file("challenge_public/seed.ct");
    auto pk = pvac_ser::deserialize_pubkey(pk_blob.data(), pk_blob.size());
    auto sk = pvac_ser::deserialize_seckey(sk_blob.data(), sk_blob.size());
    auto cts = deserialize_bundle(ct_blob);
    auto recovered = dec_text(pk, sk, cts);
    std::string expected = read_secret("verify_mnemonic = ");
    const bool ok = recovered == expected;
    wipe(recovered); wipe(expected);
    if (!ok) throw std::runtime_error("verification failed: plaintext mismatch");
    std::cout << "ok = verify\n";
}
}

int main(int argc, char** argv) {
    try {
        if (argc != 2) {
            std::cerr << "usage = " << argv[0] << " generate|verify\n";
            return 2;
        }
        const std::string mode = argv[1];
        if (mode == "generate") generate();
        else if (mode == "verify") verify();
        else throw std::runtime_error("unknown mode");
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error = " << e.what() << "\n";
        return 1;
    }
}
