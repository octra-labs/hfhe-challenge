#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <algorithm>

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
        std::cout << "=== HFHE Syndrome Decoder Analysis ===\n\n";

        std::cout << "[*] Loading artifacts...\n";
        auto pk_data = read_file("pk.bin");
        auto pk = pvac_ser::deserialize_pubkey(pk_data.data(), pk_data.size());
        
        auto ct_data = read_file("secret.ct");
        auto ciphers = deserialize_bundle(ct_data);
        std::cout << "    OK - " << ciphers.size() << " ciphertexts\n\n";

        std::cout << "[*] Analyzing Syndrome Structure\n";
        std::cout << "    H matrix: " << pk.prm.m_bits << " x " << pk.prm.n_bits << "\n";
        std::cout << "    Expected syndrome weight: " << pk.prm.err_wt << "\n\n";

        // Extract edges and analyze syndrome patterns
        if (!ciphers.empty()) {
            const auto& ct = ciphers[0];
            std::cout << "[*] Edge Syndrome Analysis (Cipher 0)\n";
            std::cout << "    Total edges: " << ct.E.size() << "\n\n";
            
            // Analyze syndrome weights
            std::vector<int> syndrome_weights;
            for (const auto& edge : ct.E) {
                if (edge.s.w.empty()) continue;
                int ones = 0;
                for (uint64_t w : edge.s.w) ones += __builtin_popcountll(w);
                syndrome_weights.push_back(ones);
            }
            
            if (!syndrome_weights.empty()) {
                std::sort(syndrome_weights.begin(), syndrome_weights.end());
                int min_wt = syndrome_weights.front();
                int max_wt = syndrome_weights.back();
                int median_wt = syndrome_weights[syndrome_weights.size()/2];
                
                std::cout << "    Syndrome weight statistics:\n";
                std::cout << "      - Min: " << min_wt << "\n";
                std::cout << "      - Max: " << max_wt << "\n";
                std::cout << "      - Median: " << median_wt << "\n";
                std::cout << "      - Expected error weight: " << pk.prm.err_wt << "\n\n";
            }
            
            // Check layer structure
            std::cout << "[*] Layer Structure Analysis\n";
            std::cout << "    Total layers: " << ct.L.size() << "\n";
            
            for (size_t i = 0; i < ct.L.size(); ++i) {
                const auto& layer = ct.L[i];
                
                // Count edges in this layer
                int layer_edges = 0;
                for (const auto& e : ct.E) {
                    if (e.layer_id == i) layer_edges++;
                }
                
                if (layer.rule == RRule::BASE) {
                    std::cout << "    Layer[" << i << "]: BASE (seed=0x" 
                              << std::hex << layer.seed.ztag << std::dec 
                              << "), edges=" << layer_edges << "\n";
                } else {
                    std::cout << "    Layer[" << i << "]: PROD (pa=" << layer.pa 
                              << ", pb=" << layer.pb << "), edges=" << layer_edges << "\n";
                }
                
                if (!layer.PC.empty()) {
                    std::cout << "      PC entries: " << layer.PC.size() << "\n";
                }
            }
        }

        std::cout << "\n[*] Attack Surface Analysis\n";
        std::cout << "    [A1] Syndrome Decoding Problem (LPN-based)\n";
        std::cout << "         - Recover private key from H via syndrome decoding\n";
        std::cout << "         - Complexity: 2^(~60) for current parameters\n\n";
        
        std::cout << "    [A2] Layer Dependency Analysis\n";
        std::cout << "         - PROD layers depend on parent layers\n";
        std::cout << "         - Check for bootstrapping issues\n\n";
        
        std::cout << "    [A3] Edge Weight Structure\n";
        std::cout << "         - Analyze Fp weights in edges\n";
        std::cout << "         - Check for small weight patterns\n\n";
        
        std::cout << "    [A4] c0 Public Component\n";
        std::cout << "         - Slot[0] public computation may leak info\n";
        std::cout << "         - Analyze contribution of each edge\n\n";

        std::cout << "[+] Analysis complete\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
}
