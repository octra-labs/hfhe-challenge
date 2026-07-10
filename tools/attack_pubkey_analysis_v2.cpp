#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include "common/logger.hpp"
#include "common/file_utils.hpp"
#include "common/analysis_utils.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <map>

using namespace pvac;
using namespace hfhe_tools;

class PubKeyAttack {
private:
    Logger& logger = get_logger();
    PubKey pk;

public:
    PubKeyAttack() {
        logger.info("=== HFHE Public Key Analysis Attack (Robust Version) ===");
    }

    bool run() {
        try {
            // Load public key
            if (!load_pubkey()) return false;

            // Run analysis
            analyze_h_matrix();
            analyze_ubk();
            analyze_powg_b();
            detect_vulnerabilities();

            logger.info("\n✓ Analysis complete");
            return true;
        } catch (const std::exception& e) {
            logger.critical("Fatal error: " + std::string(e.what()));
            return false;
        }
    }

private:
    bool load_pubkey() {
        try {
            logger.info("[*] Loading public key...");
            auto pk_data = FileUtils::read_file_strict("pk.bin");
            pk = pvac_ser::deserialize_pubkey(pk_data.data(), pk_data.size());
            logger.info("  ✓ Public key loaded (" + std::to_string(pk_data.size()) + " bytes)");
            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to load public key: " + std::string(e.what()));
            return false;
        }
    }

    void analyze_h_matrix() {
        logger.info("\n[*] H Matrix Analysis:");
        std::cout << "    Dimensions: " << pk.prm.m_bits << " x " << pk.prm.n_bits << "\n";
        std::cout << "    Columns: " << pk.H.size() << "\n";
        std::cout << "    Expected column weight: " << pk.prm.h_col_wt << "\n\n";

        // Weight statistics
        auto stats = AnalysisUtils::compute_h_weight_stats(pk.H);
        logger.info("  Weight Distribution:");
        std::cout << "    - Min: " << stats.min_weight << "\n";
        std::cout << "    - Max: " << stats.max_weight << "\n";
        std::cout << "    - Avg: " << std::fixed << std::setprecision(2) << stats.avg_weight << "\n";
        std::cout << "    - Median: " << std::fixed << std::setprecision(2) << stats.median_weight << "\n";
        std::cout << "    - Std Dev: " << std::fixed << std::setprecision(2) << stats.std_dev << "\n";
        std::cout << "    - Variance: " << std::fixed << std::setprecision(2)
                  << (stats.avg_weight - pk.prm.h_col_wt) << "\n\n";

        // Weight anomalies
        logger.info("  Anomalous Columns (weight deviation > 5):");
        int anomaly_count = 0;
        for (size_t i = 0; i < pk.H.size() && anomaly_count < 10; ++i) {
            int weight = 0;
            for (uint64_t w : pk.H[i].w) weight += __builtin_popcountll(w);
            int dev = std::abs(weight - pk.prm.h_col_wt);
            if (dev > 5) {
                std::cout << "    Column[" << i << "]: weight=" << weight
                          << " (dev=" << dev << ")\n";
                anomaly_count++;
            }
        }
        if (anomaly_count == 0) {
            std::cout << "    None found\n";
        }
    }

    void analyze_ubk() {
        logger.info("\n[*] UBK (Universal Basis Key) Analysis:");
        std::cout << "    Permutation size: " << pk.ubk.perm.size() << "\n";
        std::cout << "    Inverse size: " << pk.ubk.inv.size() << "\n\n";

        // Check if identity
        int identity_matches = 0;
        for (size_t i = 0; i < std::min(size_t(100), pk.ubk.perm.size()); ++i) {
            if (pk.ubk.perm[i] == static_cast<int>(i)) {
                identity_matches++;
            }
        }

        std::cout << "    Identity matches (first 100): " << identity_matches << "/100\n";
        if (identity_matches > 90) {
            logger.warn("    UBK permutation is near-identity (weak randomization!)");
        }

        // Check for fixed points
        int fixed_points = 0;
        for (size_t i = 0; i < pk.ubk.perm.size(); ++i) {
            if (pk.ubk.perm[i] == static_cast<int>(i)) {
                fixed_points++;
            }
        }
        std::cout << "    Total fixed points: " << fixed_points << "\n";
    }

    void analyze_powg_b() {
        logger.info("\n[*] powg_B Analysis:");
        std::cout << "    Size: " << pk.powg_B.size() << " (expected: " << pk.prm.B << ")\n";

        if (pk.powg_B.size() > 0) {
            logger.info("  First 5 values:");
            for (size_t i = 0; i < std::min(size_t(5), pk.powg_B.size()); ++i) {
                std::cout << "    [" << i << "]: (lo=0x" << std::hex << std::setfill('0')
                          << std::setw(16) << pk.powg_B[i].lo << ", hi=0x"
                          << std::setw(16) << pk.powg_B[i].hi << std::dec << ")\n";
            }
        }
    }

    void detect_vulnerabilities() {
        logger.info("\n[*] Vulnerability Detection:");
        std::cout << "\n    [W1] Linear Dependencies in GF(2):\n";
        std::cout << "         - Need Gaussian elimination on H^T\n";
        std::cout << "         - If rank < " << pk.prm.m_bits << ": potential weakness\n";
        std::cout << "         - Status: Requires advanced analysis\n\n";

        // Column duplication
        std::cout << "    [W2] Column Duplication:\n";
        auto duplicates = AnalysisUtils::find_duplicate_columns(pk.H);
        if (duplicates.empty()) {
            std::cout << "         - No duplicates found (good)\n\n";
        } else {
            logger.critical("         - Found " + std::to_string(duplicates.size()) +
                           " duplicate pairs (CRITICAL VULNERABILITY!)");
            for (size_t i = 0; i < std::min(duplicates.size(), size_t(3)); ++i) {
                std::cout << "         Column[" << duplicates[i].first << "] == Column["
                          << duplicates[i].second << "]\n";
            }
            std::cout << "\n";
        }

        // Parity analysis
        std::cout << "    [W3] Parity Structure:\n";
        auto [even_count, odd_count] = AnalysisUtils::compute_h_parity(pk.H);
        double even_pct = (100.0 * even_count) / (even_count + odd_count);
        std::cout << "         - Even parity: " << even_count << " (" << std::fixed
                  << std::setprecision(1) << even_pct << "%)\n";
        std::cout << "         - Odd parity: " << odd_count << " (" << (100 - even_pct) << "%)\n";
        if (even_pct < 45 || even_pct > 55) {
            logger.warn("         Unusual parity distribution detected!");
        }
        std::cout << "\n";

        // Summary
        logger.info("[*] Summary:");
        bool has_issues = false;
        if (!duplicates.empty()) {
            std::cout << "    ⚠ CRITICAL: Duplicate columns found\n";
            has_issues = true;
        }
        if (std::abs(AnalysisUtils::compute_h_weight_stats(pk.H).avg_weight - pk.prm.h_col_wt) > 20) {
            std::cout << "    ⚠ WARNING: Significant weight deviation\n";
            has_issues = true;
        }
        if (even_pct < 45 || even_pct > 55) {
            std::cout << "    ⚠ WARNING: Skewed parity distribution\n";
            has_issues = true;
        }
        if (!has_issues) {
            std::cout << "    ✓ No obvious structural weaknesses detected\n";
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

    PubKeyAttack attacker;
    bool success = attacker.run();

    return success ? 0 : 1;
}
