#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include "common/logger.hpp"
#include "common/file_utils.hpp"
#include "common/bundle_deserializer.hpp"
#include "common/analysis_utils.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>

using namespace pvac;
using namespace hfhe_tools;

class PlaintextRecovery {
private:
    Logger& logger = get_logger();
    PubKey pk;
    std::vector<Cipher> ciphers;

public:
    PlaintextRecovery() {
        logger.info("=== HFHE Plaintext Recovery Utility (Robust Version) ===");
    }

    bool run() {
        try {
            // Load artifacts
            if (!load_artifacts()) return false;

            // Verify structure
            if (!verify_structure()) return false;

            // Run attack vectors
            run_attack_vectors();

            logger.info("\n✓ Recovery analysis complete");
            return true;
        } catch (const std::exception& e) {
            logger.critical("Fatal error: " + std::string(e.what()));
            return false;
        }
    }

private:
    bool load_artifacts() {
        try {
            logger.info("[*] Loading artifacts...");

            // Load public key
            auto pk_data = FileUtils::read_file_strict("pk.bin");
            pk = pvac_ser::deserialize_pubkey(pk_data.data(), pk_data.size());
            logger.debug("  Public key: " + std::to_string(pk_data.size()) + " bytes");

            // Load ciphertext
            auto ct_data = FileUtils::read_file_strict("secret.ct");
            BundleStats stats;
            ciphers = BundleDeserializer::deserialize_bundle_strict(ct_data, &stats);
            logger.info("  ✓ Loaded " + std::to_string(ciphers.size()) + " ciphertexts");

            if (stats.deserialization_failures > 0) {
                logger.warn("  " + std::to_string(stats.deserialization_failures) +
                           " deserialization failures encountered");
            }

            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to load artifacts: " + std::string(e.what()));
            return false;
        }
    }

    bool verify_structure() {
        try {
            logger.info("\n[*] Verifying ciphertext structure...");

            size_t compatible_count = 0;
            for (size_t i = 0; i < ciphers.size(); ++i) {
                if (is_cipher_compatible_with_pubkey(pk, ciphers[i])) {
                    compatible_count++;
                } else {
                    logger.warn("Cipher[" + std::to_string(i) + "] incompatible");
                }
            }

            logger.info("  ✓ " + std::to_string(compatible_count) + "/" +
                       std::to_string(ciphers.size()) + " ciphers compatible");
            return compatible_count > 0;
        } catch (const std::exception& e) {
            logger.error("Structure verification failed: " + std::string(e.what()));
            return false;
        }
    }

    void run_attack_vectors() {
        logger.info("\n[*] Testing Attack Vectors...");

        // A1: Public zero leakage detection
        logger.info("\n  [A1] Public Zero Leakage Detection:");
        if (!ciphers.empty()) {
            const auto& ct0 = ciphers[0];
            int public_zero_count = 0;
            int base_layer_count = 0;

            for (size_t i = 0; i < ct0.L.size(); ++i) {
                if (ct0.L[i].rule != RRule::BASE) continue;
                base_layer_count++;

                Fp acc = ct0.c0.empty() ? fp_from_u64(0) : ct0.c0[0];
                for (const auto& e : ct0.E) {
                    if (e.layer_id != i) continue;
                    if (!e.w.empty() && e.idx < pk.powg_B.size()) {
                        Fp term = fp_mul(e.w[0], pk.powg_B[e.idx]);
                        acc = sgn_val(e.ch) > 0 ? fp_add(acc, term) : fp_sub(acc, term);
                    }
                }

                if (acc.lo == 0 && acc.hi == 0) {
                    public_zero_count++;
                }
            }

            std::cout << "       Base layers: " << base_layer_count << "\n";
            std::cout << "       Public zeros found: " << public_zero_count << "\n";

            if (public_zero_count > 0) {
                logger.warn("       POTENTIAL WEAKNESS: Public zeros detected!");
            }
        }

        // A2: H matrix properties
        logger.info("\n  [A2] H Matrix Property Analysis:");
        auto h_stats = AnalysisUtils::compute_h_weight_stats(pk.H);
        auto [even_count, odd_count] = AnalysisUtils::compute_h_parity(pk.H);

        std::cout << "       Weight deviation from expected: "
                  << (h_stats.avg_weight - pk.prm.h_col_wt) << "\n";
        std::cout << "       Even/Odd parity ratio: " << even_count << "/" << odd_count << "\n";

        if (std::abs(h_stats.avg_weight - pk.prm.h_col_wt) > 20) {
            logger.warn("       ANOMALY: Significant weight deviation!");
        }

        // A3: LPN parameter assessment
        logger.info("\n  [A3] LPN Parameter Analysis:");
        std::cout << "       LPN n: " << pk.prm.lpn_n << "\n";
        std::cout << "       LPN t: " << pk.prm.lpn_t << "\n";
        std::cout << "       Ratio t/n: " << std::fixed << std::setprecision(2)
                  << (double)pk.prm.lpn_t / pk.prm.lpn_n << "\n";
        std::cout << "       Error weight: " << pk.prm.err_wt << "\n";
        std::cout << "       Field bits: 127\n";

        // A4: Syndrome weight distribution
        if (!ciphers.empty()) {
            logger.info("\n  [A4] Syndrome Weight Distribution:");
            auto syndrome_stats = AnalysisUtils::compute_syndrome_weight_stats(ciphers[0].E);
            std::cout << "       Min syndrome weight: " << syndrome_stats.min_weight << "\n";
            std::cout << "       Max syndrome weight: " << syndrome_stats.max_weight << "\n";
            std::cout << "       Avg syndrome weight: " << std::fixed << std::setprecision(2)
                      << syndrome_stats.avg_weight << "\n";
            std::cout << "       Expected error weight: " << pk.prm.err_wt << "\n";
        }
    }
};

int main(int argc, char** argv) {
    // Configure logger
    auto& logger = get_logger();
    if (argc > 1 && std::string(argv[1]) == "--verbose") {
        logger.set_level(LogLevel::DEBUG);
    } else {
        logger.set_level(LogLevel::INFO);
    }

    PlaintextRecovery recovery;
    bool success = recovery.run();

    return success ? 0 : 1;
}
