// probe.cpp — recompute T_L = sum(sign * w * g^idx) for all layers of secret.ct
// This is the only public quantity that depends on the plaintext.
// T_L = target_L * R_L, where target = v+m (layer 0) or -m (layer 1).
//
// Build: g++ -std=c++17 -O2 -march=native -maes -Ipvac_hfhe_cpp/include -Isource probe.cpp -o probe
// Usage: ./probe <challenge_dir>   (default: current dir)

#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

using namespace pvac;

std::vector<uint8_t> read_file(const char* path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error(std::string("cannot open ") + path);
    f.seekg(0, std::ios::end);
    size_t n = f.tellg(); f.seekg(0, std::ios::beg);
    std::vector<uint8_t> d(n);
    f.read((char*)d.data(), n);
    return d;
}

Fp compute_T(const PubKey& pk, const Cipher& c, uint32_t lid) {
    Fp acc = (lid == 0 && !c.c0.empty()) ? c.c0[0] : fp_from_u64(0);
    for (const auto& e : c.E) {
        if (e.layer_id != lid) continue;
        Fp term = fp_mul(e.w[0], pk.powg_B[e.idx]);
        acc = (sgn_val(e.ch) > 0) ? fp_add(acc, term) : fp_sub(acc, term);
    }
    return acc;
}

int main(int argc, char** argv) {
    std::string dir = (argc > 1) ? argv[1] : ".";
    
    auto pk_data = read_file((dir + "/pk.bin").c_str());
    auto ct_data = read_file((dir + "/secret.ct").c_str());
    
    auto pk = pvac_ser::deserialize_pubkey(pk_data.data(), pk_data.size());
    
    size_t pos = 16; // skip magic + version
    auto read64 = [&]() -> uint64_t {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= (uint64_t)ct_data[pos++] << (8 * i);
        return v;
    };
    
    uint64_t ncts = read64();
    std::vector<Cipher> cts;
    for (uint64_t i = 0; i < ncts; ++i) {
        uint64_t blob_size = read64();
        std::vector<uint8_t> blob(ct_data.begin() + pos, ct_data.begin() + pos + blob_size);
        pos += blob_size;
        cts.push_back(pvac_ser::deserialize_cipher(blob.data(), blob.size()));
    }
    
    std::cout << "pk.B=" << pk.prm.B << " pk.H=" << pk.H.size() 
              << " ciphers=" << cts.size() << "\n\n";
    
    // Check seed uniqueness
    std::vector<uint64_t> all_ztags;
    for (const auto& c : cts) {
        for (const auto& L : c.L) {
            all_ztags.push_back(L.seed.ztag);
        }
    }
    
    std::sort(all_ztags.begin(), all_ztags.end());
    auto last = std::unique(all_ztags.begin(), all_ztags.end());
    bool all_unique = (last == all_ztags.end());
    std::cout << "All " << all_ztags.size() << " seeds unique: " 
              << (all_unique ? "YES" : "NO") << "\n\n";
    
    // Compute T_L for all layers
    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < cts.size(); ++i) {
        const auto& c = cts[i];
        size_t nlayers = c.L.size();
        
        for (size_t lid = 0; lid < nlayers; ++lid) {
            Fp T = compute_T(pk, c, (uint32_t)lid);
            std::string rule = (c.L[lid].rule == RRule::BASE) ? "BASE" : 
                              (c.L[lid].rule == RRule::PROD) ? "PROD" : "NATIVE";
            
            std::cout << "ct[" << std::dec << i << std::hex << "].L[" << lid << "]"
                      << " (" << rule << ") "
                      << "seed=" << std::setw(16) << c.L[lid].seed.ztag
                      << " T=" << std::setw(16) << (T.hi & MASK63) << std::setw(16) << T.lo
                      << " edges=" << std::dec;
            
            size_t edge_count = 0;
            for (const auto& e : c.E) {
                if (e.layer_id == lid) edge_count++;
            }
            std::cout << edge_count << std::hex << "\n";
        }
    }
    
    // Verify: T0 + T1 should NOT equal v*R (because R0 != R1)
    // But T0/R0 + T1/R1 = v for correct key
    std::cout << "\n=== Summary ===\n";
    std::cout << "Total layers: " << std::dec << all_ztags.size() << "\n";
    std::cout << "All seeds unique: " << (all_unique ? "YES" : "NO") << "\n";
    std::cout << "T values are the ONLY public quantity depending on plaintext.\n";
    std::cout << "Each T = target * R, with R = prf_R(sk, seed).\n";
    std::cout << "Without sk, R is computationally indistinguishable from uniform.\n";
    
    return 0;
}
