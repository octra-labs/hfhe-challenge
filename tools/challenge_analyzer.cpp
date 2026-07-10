#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstring>

using namespace pvac;

// Read binary file
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

void print_hex(const std::vector<uint8_t>& data, size_t max_bytes = 64) {
    size_t n = std::min(data.size(), max_bytes);
    for (size_t i = 0; i < n; ++i) {
        if (i > 0 && i % 16 == 0) std::cout << "\n";
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << (int)data[i] << " ";
    }
    std::cout << std::dec << "\n";
}

void print_fp(const Fp& x) {
    std::cout << "Fp(0x" << std::hex << std::setfill('0')
              << std::setw(16) << x.hi << std::setw(16) << x.lo << std::dec << ")";
}

int main(int argc, char** argv) {
    try {
        std::cout << "=== HFHE Challenge v2 Analyzer ===\n\n";

        // Load public key
        std::cout << "[*] Loading public key from pk.bin...\n";
        auto pk_data = read_file("pk.bin");
        std::cout << "    - Size: " << pk_data.size() << " bytes\n";
        auto pk = pvac_ser::deserialize_pubkey(pk_data.data(), pk_data.size());
        std::cout << "    - Deserialized successfully\n\n";

        // Load ciphertext bundle
        std::cout << "[*] Loading ciphertext from secret.ct...\n";
        auto ct_data = read_file("secret.ct");
        std::cout << "    - Size: " << ct_data.size() << " bytes\n";
        
        // Check magic
        constexpr std::array<uint8_t, 16> BUNDLE_MAGIC = {
            'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'
        };
        if (ct_data.size() >= 16 && std::equal(BUNDLE_MAGIC.begin(), BUNDLE_MAGIC.end(), ct_data.begin())) {
            std::cout << "    - Valid HFHE bundle magic found\n";
        }

        // Extract cipher count
        uint64_t cipher_count = 0;
        if (ct_data.size() >= 24) {
            std::memcpy(&cipher_count, &ct_data[16], 8);
            std::cout << "    - Ciphertext count: " << cipher_count << "\n";
        }

        // Parse ciphertexts
        size_t pos = 24;
        std::vector<Cipher> ciphers;
        for (uint64_t i = 0; i < cipher_count && i < 10; ++i) {
            if (pos + 8 > ct_data.size()) break;
            uint64_t ct_len = 0;
            std::memcpy(&ct_len, &ct_data[pos], 8);
            pos += 8;
            if (pos + ct_len > ct_data.size()) break;
            
            try {
                Cipher c = pvac_ser::deserialize_cipher(&ct_data[pos], ct_len);
                ciphers.push_back(c);
                pos += ct_len;
            } catch (...) {
                std::cerr << "    - Error deserializing cipher " << i << "\n";
                break;
            }
        }
        std::cout << "    - Successfully deserialized " << ciphers.size() << " ciphertexts\n\n";

        // Public Key Analysis
        std::cout << "[*] Public Key Structure:\n";
        std::cout << "    - Parameters B: " << pk.prm.B << "\n";
        std::cout << "    - Matrix dimensions: " << pk.prm.m_bits << " x " << pk.prm.n_bits << "\n";
        std::cout << "    - H columns (dim n): " << pk.H.size() << "\n";
        std::cout << "    - H column weight: " << pk.prm.h_col_wt << "\n";
        std::cout << "    - powg_B size: " << pk.powg_B.size() << "\n";
        std::cout << "    - UBK perm size: " << pk.ubk.perm.size() << "\n";
        std::cout << "    - UBK inv size: " << pk.ubk.inv.size() << "\n\n";

        // H matrix statistics
        std::cout << "[*] H Matrix Analysis (first 5 columns):\n";
        for (size_t i = 0; i < std::min(size_t(5), pk.H.size()); ++i) {
            const auto& col = pk.H[i];
            int ones = 0;
            for (uint64_t w : col.w) ones += __builtin_popcountll(w);
            std::cout << "    - H[" << i << "]: " << ones << " ones\n";
        }
        std::cout << "\n";

        // Cipher Analysis
        std::cout << "[*] Ciphertext Structure Analysis:\n";
        for (size_t i = 0; i < std::min(size_t(2), ciphers.size()); ++i) {
            const auto& ct = ciphers[i];
            std::cout << "    Cipher[" << i << "]:\n";
            std::cout << "      - Slots: " << ct.slots << "\n";
            std::cout << "      - Layers: " << ct.L.size() << "\n";
            std::cout << "      - Edges: " << ct.E.size() << "\n";
            std::cout << "      - c0 entries: " << ct.c0.size() << "\n";
            
            // Layer analysis
            size_t base_layers = 0;
            for (size_t j = 0; j < ct.L.size(); ++j) {
                if (ct.L[j].rule == RRule::BASE) {
                    base_layers++;
                    std::cout << "      - Layer[" << j << "]: BASE (seed: 0x" 
                              << std::hex << ct.L[j].seed.ztag << std::dec << ")\n";
                } else {
                    std::cout << "      - Layer[" << j << "]: PROD (pa=" 
                              << ct.L[j].pa << ", pb=" << ct.L[j].pb << ")\n";
                }
            }
            std::cout << "      - Total BASE layers: " << base_layers << "\n";
            
            // First few edges
            if (ct.E.size() > 0) {
                std::cout << "      - First edge: layer_id=" << ct.E[0].layer_id 
                          << ", idx=" << ct.E[0].idx << ", weights=" << ct.E[0].w.size() << "\n";
            }
            std::cout << "\n";
        }

        // Potential vulnerability checks
        std::cout << "[*] Security Checks:\n";
        
        // Check if base layers have public zero at slot 0
        bool has_public_zero = false;
        if (!ciphers.empty()) {
            const auto& ct0 = ciphers[0];
            for (size_t i = 0; i < ct0.L.size(); ++i) {
                if (ct0.L[i].rule != RRule::BASE) continue;
                Fp slot0 = ct0.c0.empty() ? fp_from_u64(0) : ct0.c0[0];
                for (const auto& e : ct0.E) {
                    if (e.layer_id != i) continue;
                    if (!e.w.empty()) {
                        Fp term = fp_mul(e.w[0], pk.powg_B[e.idx]);
                        slot0 = sgn_val(e.ch) > 0 ? fp_add(slot0, term) : fp_sub(slot0, term);
                    }
                }
                if (slot0.lo == 0 && slot0.hi == 0) {
                    has_public_zero = true;
                    break;
                }
            }
        }
        std::cout << "    - Public zero found: " << (has_public_zero ? "YES" : "NO") << "\n";
        std::cout << "    - Wrapped format (2 base layers): " << (ciphers.size() >= 2 ? "YES" : "NO") << "\n";
        
        std::cout << "\n[+] Analysis complete!\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
}
