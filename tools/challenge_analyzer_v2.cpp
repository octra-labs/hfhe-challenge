#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include "common/logger.hpp"
#include "common/file_utils.hpp"
#include "common/bundle_deserializer.hpp"
#include "common/analysis_utils.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <map>

using namespace pvac;
using namespace hfhe_tools;

class ChallengeAnalyzer {
private:
    Logger& logger = get_logger();
    std::string verbose_flag;

public:
    ChallengeAnalyzer() {
        logger.info("=== HFHE Challenge v2 Analyzer (Robust Version) ===");
    }

    bool run(bool verbose = false) {
        try {
            // Load public key
            if (!load_and_analyze_pubkey()) return false;

            // Load and analyze ciphertext
            if (!load_and_analyze_ciphertext()) return false;

            // Run security checks
            if (!run_security_checks()) return false;

            logger.info("✓ Analysis complete successfully");
            return true;
        } catch (const std::exception& e) {
            logger.critical("Fatal error: " + std::string(e.what()));
            return false;
        }
    }

private:
    bool load_and_analyze_pubkey() {
        try {
            logger.info("[*] Loading public key...");
            auto pk_data = FileUtils::read_file_strict("pk.bin");
            logger.debug("  Size: " + std::to_string(pk_data.size()) + " bytes");

            auto pk = pvac_ser::deserialize_pubkey(pk_data.data(), pk_data.size());
            logger.info("  ✓ Public key deserialized successfully");

            // Analyze structure
            logger.info("\n[*] Public Key Structure:");
            std::cout << "    - Parameters B: " << pk.prm.B << "\n";
            std::cout << "    - Matrix dimensions: " << pk.prm.m_bits << " x "
                      << pk.prm.n_bits << "\n";
            std::cout << "    - H columns: " << pk.H.size() << "\n";
            std::cout << "    - H column weight: " << pk.prm.h_col_wt << "\n";
            std::cout << "    - powg_B entries: " << pk.powg_B.size() << "\n";
            std::cout << "    - UBK perm size: " << pk.ubk.perm.size() << "\n";
            std::cout << "    - UBK inv size: " << pk.ubk.inv.size() << "\n\n";

            // H matrix weight statistics
            logger.info("[*] H Matrix Weight Analysis:");
            auto h_stats = AnalysisUtils::compute_h_weight_stats(pk.H);
            std::cout << "    - Min weight: " << h_stats.min_weight << "\n";
            std::cout << "    - Max weight: " << h_stats.max_weight << "\n";
            std::cout << "    - Avg weight: " << std::fixed << std::setprecision(2)
                      << h_stats.avg_weight << "\n";
            std::cout << "    - Median weight: " << h_stats.median_weight << "\n";
            std::cout << "    - Std dev: " << h_stats.std_dev << "\n";
            std::cout << "    - Expected: " << pk.prm.h_col_wt << "\n\n";

            if (std::abs(h_stats.avg_weight - pk.prm.h_col_wt) > 10) {
                logger.warn("H matrix weight deviation detected!");
            }

            // Parity analysis
            logger.info("[*] H Matrix Parity Analysis:");
            auto [even_count, odd_count] = AnalysisUtils::compute_h_parity(pk.H);
            double even_pct = (100.0 * even_count) / (even_count + odd_count);
            double odd_pct = (100.0 * odd_count) / (even_count + odd_count);
            std::cout << "    - Even parity columns: " << even_count
                      << " (" << std::fixed << std::setprecision(1) << even_pct << "%)\n";
            std::cout << "    - Odd parity columns: " << odd_count
                      << " (" << std::fixed << std::setprecision(1) << odd_pct << "%)\n";
            std::cout << "    - Expected ratio: ~50% each\n\n";

            if (even_pct < 45 || even_pct > 55) {
                logger.warn("Parity distribution is skewed!");
            }

            // Duplicate column detection
            logger.info("[*] Duplicate Column Detection:");
            auto duplicates = AnalysisUtils::find_duplicate_columns(pk.H);
            if (duplicates.empty()) {
                std::cout << "    - No duplicate columns found (good)\n\n";
            } else {
                logger.warn("Found " + std::to_string(duplicates.size()) +
                           " duplicate column pairs (potential weakness!)");
                for (size_t i = 0; i < std::min(duplicates.size(), size_t(5)); ++i) {
                    std::cout << "      Column[" << duplicates[i].first << "] == Column["
                              << duplicates[i].second << "]\n";
                }
                std::cout << "\n";
            }

            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to load public key: " + std::string(e.what()));
            return false;
        }
    }

    bool load_and_analyze_ciphertext() {
        try {
            logger.info("[*] Loading ciphertext bundle...");
            auto ct_data = FileUtils::read_file_strict("secret.ct");
            logger.debug("  Size: " + std::to_string(ct_data.size()) + " bytes");

            // Deserialize with statistics
            BundleStats stats;
            auto ciphers = BundleDeserializer::deserialize_bundle_strict(ct_data, &stats);
            logger.info("  ✓ Bundle deserialized: " + std::to_string(stats.successfully_deserialized) +
                       "/" + std::to_string(stats.cipher_count) + " ciphers");

            // Ciphertext structure analysis
            logger.info("\n[*] Ciphertext Structure Analysis:");
            std::cout << "    - Total ciphers: " << ciphers.size() << "\n";
            std::cout << "    - Total bytes: " << stats.total_bytes << "\n";
            std::cout << "    - Deserialization failures: " << stats.deserialization_failures << "\n";

            if (!stats.error_messages.empty()) {
                logger.warn("Encountered " + std::to_string(stats.error_messages.size()) +
                           " errors during deserialization");
                for (size_t i = 0; i < std::min(stats.error_messages.size(), size_t(3)); ++i) {
                    logger.debug("  - " + stats.error_messages[i]);
                }
            }

            // Analyze first few ciphers
            logger.info("\n[*] Cipher Details (first 3):");
            for (size_t i = 0; i < std::min(ciphers.size(), size_t(3)); ++i) {
                const auto& ct = ciphers[i];
                std::cout << "    Cipher[" << i << "]:\n";
                std::cout << "      - Slots: " << ct.slots << "\n";
                std::cout << "      - Layers: " << ct.L.size() << "\n";
                std::cout << "      - Edges: " << ct.E.size() << "\n";
                std::cout << "      - c0 entries: " << ct.c0.size() << "\n";

                // Count base layers
                size_t base_count = 0;
                for (const auto& l : ct.L) {
                    if (l.rule == RRule::BASE) base_count++;
                }
                std::cout << "      - Base layers: " << base_count << "\n";

                if (i < 2) std::cout << "\n";
            }

            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to load ciphertext: " + std::string(e.what()));
            return false;
        }
    }

    bool run_security_checks() {
        try {
            logger.info("\n[*] Security Checks:");

            // Check file integrity
            if (!FileUtils::file_exists("pk.bin")) {
                logger.warn("pk.bin not found");
                return false;
            }

            if (!FileUtils::file_exists("secret.ct")) {
                logger.warn("secret.ct not found");
                return false;
            }

            if (!FileUtils::file_exists("params.json")) {
                logger.warn("params.json not found");
            }

            logger.info("  ✓ All required artifacts present");

            // Check bundle magic
            auto ct_data = FileUtils::read_file_strict("secret.ct");
            if (!BundleDeserializer::validate_magic(ct_data)) {
                logger.error("Invalid bundle magic number!");
                return false;
            }
            logger.info("  ✓ Bundle magic valid");

            // Verify cipher count
            uint64_t count = BundleDeserializer::get_cipher_count(ct_data);
            logger.info("  ✓ Bundle cipher count: " + std::to_string(count));

            return true;
        } catch (const std::exception& e) {
            logger.error("Security checks failed: " + std::string(e.what()));
            return false;
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

    ChallengeAnalyzer analyzer;
    bool success = analyzer.run(argc > 1 && std::string(argv[1]) == "--verbose");

    return success ? 0 : 1;
}
