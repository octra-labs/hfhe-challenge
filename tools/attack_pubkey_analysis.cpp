#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <set>
#include <map>
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

int main(int argc, char** argv) {
    try {
        std::cout << "=== HFHE Public Key Analysis Attack ===\n\n";

        std::cout << "[*] Loading public key...\n";
        auto pk_data = read_file("pk.bin");
        auto pk = pvac_ser::deserialize_pubkey(pk_data.data(), pk_data.size());
        std::cout << "    OK\n\n";

        // Analysis 1: H matrix structure
        std::cout << "[*] H Matrix Structure Analysis\n";
        std::cout << "    Dimensions: " << pk.prm.m_bits << " x " << pk.prm.n_bits << "\n";
        std::cout << "    Expected column weight: " << pk.prm.h_col_wt << "\n\n";

        // Collect weight distribution
        std::vector<int> weights;
        std::map<int, int> weight_dist;
        
        for (size_t i = 0; i < pk.H.size(); ++i) {
            int ones = 0;
            for (uint64_t w : pk.H[i].w) ones += __builtin_popcountll(w);
            weights.push_back(ones);
            weight_dist[ones]++;
        }
        
        // Statistics
        int min_weight = *std::min_element(weights.begin(), weights.end());
        int max_weight = *std::max_element(weights.begin(), weights.end());
        double avg_weight = 0;
        for (int w : weights) avg_weight += w;
        avg_weight /= weights.size();
        
        std::cout << "    Weight distribution:\n";
        std::cout << "      - Min: " << min_weight << "\n";
        std::cout << "      - Max: " << max_weight << "\n";
        std::cout << "      - Avg: " << avg_weight << "\n";
        std::cout << "      - Variance from expected (" << pk.prm.h_col_wt << "): "
                  << (avg_weight - pk.prm.h_col_wt) << "\n\n";

        // Check for degenerate columns
        std::cout << "    Columns with weight deviations:\n";
        int anomalies = 0;
        for (size_t i = 0; i < weights.size() && anomalies < 10; ++i) {
            int dev = std::abs(weights[i] - pk.prm.h_col_wt);
            if (dev > 5) {
                std::cout << "      Column[" << i << "]: weight=" << weights[i] << "\n";
                anomalies++;
            }
        }

        // Analysis 2: UBK permutation
        std::cout << "\n[*] UBK (Universal Basis Key) Analysis\n";
        std::cout << "    Perm size: " << pk.ubk.perm.size() << "\n";
        std::cout << "    Inv size: " << pk.ubk.inv.size() << "\n";
        
        // Check if it's identity or near-identity
        int identity_matches = 0;
        for (size_t i = 0; i < std::min(size_t(100), pk.ubk.perm.size()); ++i) {
            if (pk.ubk.perm[i] == (int)i) identity_matches++;
        }
        std::cout << "    Identity matches (first 100): " << identity_matches << "\n\n";

        // Analysis 3: powg_B computation
        std::cout << "[*] powg_B Analysis\n";
        std::cout << "    Size: " << pk.powg_B.size() << " (should be B=" << pk.prm.B << ")\n";
        
        if (pk.powg_B.size() > 0) {
            // Check if values are monotonic or have pattern
            std::cout << "    First 5 values (Fp):";
            for (size_t i = 0; i < std::min(size_t(5), pk.powg_B.size()); ++i) {
                std::cout << " [" << i << "]=(" << pk.powg_B[i].lo << "," 
                          << pk.powg_B[i].hi << ")";
            }
            std::cout << "\n\n";
        }

        // Analysis 4: Potential weaknesses
        std::cout << "[*] Potential Weaknesses\n";
        
        // 1. Check for linear dependencies in H
        std::cout << "    [W1] Linear dependencies in GF(2)\n";
        std::cout << "         - Need Gaussian elimination on H^T\n";
        std::cout << "         - If rank < m_bits: syndrome decoding attack may exist\n\n";
        
        // 2. Check column repetitions
        std::map<std::vector<uint64_t>, int> col_map;
        int duplicates = 0;
        for (size_t i = 0; i < pk.H.size(); ++i) {
            if (col_map[pk.H[i].w]++ > 0) duplicates++;
        }
        std::cout << "    [W2] Column duplicates: " << duplicates << "\n";
        if (duplicates > 0) {
            std::cout << "         CRITICAL: Duplicate columns leak information!\n\n";
        } else {
            std::cout << "\n";
        }
        
        // 3. Parity analysis
        std::cout << "    [W3] Parity structure\n";
        std::vector<int> parities;
        for (const auto& col : pk.H) {
            int ones = 0;
            for (uint64_t w : col.w) ones += __builtin_popcountll(w);
            parities.push_back(ones & 1);
        }
        
        int parity_0 = std::count(parities.begin(), parities.end(), 0);
        int parity_1 = std::count(parities.begin(), parities.end(), 1);
        double parity_ratio = (double)parity_1 / (parity_0 + parity_1);
        
        std::cout << "         Even parity: " << parity_0 << " (" << (100*parity_0/(parity_0+parity_1)) << "%)\n";
        std::cout << "         Odd parity: " << parity_1 << " (" << (100*parity_1/(parity_0+parity_1)) << "%)\n";
        std::cout << "         Ratio: " << parity_ratio << " (should be ~0.5)\n";
        
        if (parity_ratio < 0.45 || parity_ratio > 0.55) {
            std::cout << "         WARNING: Unusual parity distribution!\n\n";
        } else {
            std::cout << "\n";
        }

        std::cout << "[+] Analysis complete!\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
}
