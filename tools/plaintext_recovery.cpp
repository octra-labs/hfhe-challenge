#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstring>

using namespace pvac;

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open: " + path);
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

// Deserialize bundle (copied from artifact)
std::vector<Cipher> deserialize_bundle(const std::vector<uint8_t>& in) {
    constexpr std::array<uint8_t, 16> BUNDLE_MAGIC = {
        'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'
    };
    
    if (in.size() < 16 || !std::equal(BUNDLE_MAGIC.begin(), BUNDLE_MAGIC.end(), in.begin())) {
        throw std::runtime_error("bad secret.ct magic");
    }
    
    size_t pos = 16;
    uint64_t count = 0;
    std::memcpy(&count, &in[pos], 8);
    pos += 8;
    
    if (count == 0 || count > 1024) {
        throw std::runtime_error("invalid cipher count");
    }
    
    std::vector<Cipher> cts;
    cts.reserve(static_cast<size_t>(count));
    
    for (uint64_t i = 0; i < count; ++i) {
        if (pos + 8 > in.size()) throw std::runtime_error("truncated secret.ct");
        
        uint64_t n = 0;
        std::memcpy(&n, &in[pos], 8);
        pos += 8;
        
        if (n == 0 || n > in.size() - pos) {
            throw std::runtime_error("invalid cipher length");
        }
        
        cts.push_back(pvac_ser::deserialize_cipher(in.data() + pos, static_cast<size_t>(n)));
        pos += static_cast<size_t>(n);
    }
    
    if (pos != in.size()) {
        throw std::runtime_error("trailing bytes in secret.ct");
    }
    
    return cts;
}

int main(int argc, char** argv) {
    try {
        std::cout << "=== HFHE Plaintext Recovery Utility ===\n\n";

        // Load public key
        std::cout << "[*] Loading public key...\n";
        auto pk_data = read_file("pk.bin");
        auto pk = pvac_ser::deserialize_pubkey(pk_data.data(), pk_data.size());
        std::cout << "    OK - Size: " << pk_data.size() << " bytes\n\n";

        // Load ciphertext
        std::cout << "[*] Loading ciphertext...\n";
        auto ct_data = read_file("secret.ct");
        std::cout << "    OK - Size: " << ct_data.size() << " bytes\n\n";

        // Deserialize
        std::cout << "[*] Deserializing ciphertext bundle...\n";
        std::vector<Cipher> ciphers = deserialize_bundle(ct_data);
        std::cout << "    OK - " << ciphers.size() << " ciphertexts loaded\n\n";

        // Structure verification
        std::cout << "[*] Verifying structure...\n";
        for (size_t i = 0; i < ciphers.size(); ++i) {
            bool compatible = is_cipher_compatible_with_pubkey(pk, ciphers[i]);
            std::cout << "    Cipher[" << i << "]: " << (compatible ? "COMPATIBLE" : "INCOMPATIBLE") << "\n";
        }
        std::cout << "\n";

        // Ciphertext analysis
        std::cout << "[*] Ciphertext Details:\n";
        for (size_t i = 0; i < ciphers.size(); ++i) {
            const auto& ct = ciphers[i];
            std::cout << "  Cipher[" << i << "]:\n";
            std::cout << "    - Slots: " << ct.slots << "\n";
            std::cout << "    - Layers: " << ct.L.size() << "\n";
            std::cout << "    - Edges: " << ct.E.size() << "\n";
            
            size_t base_count = 0;
            for (const auto& l : ct.L) {
                if (l.rule == RRule::BASE) base_count++;
            }
            std::cout << "    - Base layers: " << base_count << "\n";
        }
        std::cout << "\n";

        // ATTACK VECTOR 1: Check for structural weaknesses
        std::cout << "[*] Testing Attack Vectors...\n";
        std::cout << "\n  [A1] Checking for public zero leakage...\n";
        
        // Try to detect if base layer structure reveals information
        if (!ciphers.empty()) {
            const auto& ct0 = ciphers[0];
            int layer_num = 0;
            for (size_t i = 0; i < ct0.L.size(); ++i) {
                if (ct0.L[i].rule != RRule::BASE) continue;
                layer_num++;
                
                // Compute public portion at slot 0
                Fp acc = ct0.c0.empty() ? fp_from_u64(0) : ct0.c0[0];
                int edge_count = 0;
                
                for (const auto& e : ct0.E) {
                    if (e.layer_id != i) continue;
                    edge_count++;
                    if (!e.w.empty() && e.idx < pk.powg_B.size()) {
                        Fp term = fp_mul(e.w[0], pk.powg_B[e.idx]);
                        acc = sgn_val(e.ch) > 0 ? fp_add(acc, term) : fp_sub(acc, term);
                    }
                }
                
                bool is_zero = (acc.lo == 0 && acc.hi == 0);
                std::cout << "    Layer " << i << ": " << edge_count << " edges, "
                          << "slot0_public = " << (is_zero ? "ZERO" : "NONZERO") << "\n";
            }
        }

        std::cout << "\n  [A2] Checking H matrix properties...\n";
        // Compute parity of H columns
        int parity_count[2] = {0, 0};
        for (size_t i = 0; i < std::min(size_t(256), pk.H.size()); ++i) {
            int ones = 0;
            for (uint64_t w : pk.H[i].w) ones += __builtin_popcountll(w);
            parity_count[ones & 1]++;
        }
        std::cout << "    Even parity columns: " << parity_count[0] << "\n";
        std::cout << "    Odd parity columns: " << parity_count[1] << "\n";
        std::cout << "    Mixed parity: " << (parity_count[0] > 0 && parity_count[1] > 0 ? "YES" : "NO") << "\n";

        std::cout << "\n  [A3] LPN Parameter Analysis...\n";
        std::cout << "    - LPN n: " << pk.prm.lpn_n << "\n";
        std::cout << "    - LPN t: " << pk.prm.lpn_t << "\n";
        std::cout << "    - Ratio t/n: " << (double)pk.prm.lpn_t / pk.prm.lpn_n << "\n";
        std::cout << "    - Field bits: 127 (p = 2^127-1)\n";

        std::cout << "\n[*] Analysis Complete\n";
        std::cout << "\n[NOTE] To decrypt: need to recover private key or find weakness in:\n";
        std::cout << "  1. LPN syndrome decoding from public key structure\n";
        std::cout << "  2. H matrix rank/dependencies\n";
        std::cout << "  3. Edge structure vulnerabilities in layers\n";
        std::cout << "  4. Information leakage from c0 public portion\n";
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
}
