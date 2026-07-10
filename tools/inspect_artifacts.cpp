#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <nlohmann/json.hpp>

using namespace pvac;
using json = nlohmann::json;

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

json fp_to_json(const Fp& x) {
    json j;
    j["lo"] = x.lo;
    j["hi"] = x.hi;
    return j;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [pk|ct|params]\n";
        return 1;
    }

    std::string cmd = argv[1];

    try {
        if (cmd == "pk") {
            std::cout << "[*] Inspecting public key...\n";
            auto pk_data = read_file("pk.bin");
            auto pk = pvac_ser::deserialize_pubkey(pk_data.data(), pk_data.size());
            
            json j;
            j["type"] = "public_key";
            j["params"]["B"] = pk.prm.B;
            j["params"]["m_bits"] = pk.prm.m_bits;
            j["params"]["n_bits"] = pk.prm.n_bits;
            j["params"]["h_col_wt"] = pk.prm.h_col_wt;
            j["H_columns"] = pk.H.size();
            j["powg_B_entries"] = pk.powg_B.size();
            j["ubk_perm_size"] = pk.ubk.perm.size();
            j["ubk_inv_size"] = pk.ubk.inv.size();
            
            std::cout << j.dump(2) << "\n";
            
        } else if (cmd == "ct") {
            std::cout << "[*] Inspecting ciphertext...\n";
            auto ct_data = read_file("secret.ct");
            
            json j;
            j["type"] = "ciphertext_bundle";
            j["total_bytes"] = ct_data.size();
            
            // Parse bundle
            constexpr std::array<uint8_t, 16> BUNDLE_MAGIC = {
                'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'
            };
            
            if (ct_data.size() >= 16 && std::equal(BUNDLE_MAGIC.begin(), BUNDLE_MAGIC.end(), ct_data.begin())) {
                j["magic_valid"] = true;
            } else {
                j["magic_valid"] = false;
            }
            
            uint64_t cipher_count = 0;
            if (ct_data.size() >= 24) {
                std::memcpy(&cipher_count, &ct_data[16], 8);
                j["cipher_count"] = cipher_count;
            }
            
            size_t pos = 24;
            json ciphers_info = json::array();
            for (uint64_t i = 0; i < std::min(cipher_count, 5UL); ++i) {
                if (pos + 8 > ct_data.size()) break;
                uint64_t ct_len = 0;
                std::memcpy(&ct_len, &ct_data[pos], 8);
                pos += 8;
                
                json ct_info;
                ct_info["index"] = i;
                ct_info["byte_length"] = ct_len;
                
                if (pos + ct_len <= ct_data.size()) {
                    try {
                        Cipher c = pvac_ser::deserialize_cipher(&ct_data[pos], ct_len);
                        ct_info["slots"] = c.slots;
                        ct_info["layers"] = c.L.size();
                        ct_info["edges"] = c.E.size();
                        ct_info["c0_entries"] = c.c0.size();
                        ciphers_info.push_back(ct_info);
                    } catch (const std::exception& e) {
                        ct_info["error"] = e.what();
                        ciphers_info.push_back(ct_info);
                    }
                }
                pos += ct_len;
            }
            j["ciphers"] = ciphers_info;
            
            std::cout << j.dump(2) << "\n";
            
        } else if (cmd == "params") {
            std::cout << "[*] Reading params.json...\n";
            std::ifstream pf("params.json");
            if (!pf) {
                std::cerr << "Cannot open params.json\n";
                return 1;
            }
            json params;
            pf >> params;
            std::cout << params.dump(2) << "\n";
        } else {
            std::cerr << "Unknown command: " << cmd << "\n";
            return 1;
        }
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << "\n";
        return 1;
    }
}
