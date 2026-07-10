#pragma once

#include <pvac/pvac.hpp>
#include <vector>
#include <map>
#include <algorithm>
#include <numeric>
#include <cmath>

namespace hfhe_tools {

struct WeightStats {
    int min_weight = 0;
    int max_weight = 0;
    double avg_weight = 0.0;
    double median_weight = 0.0;
    double std_dev = 0.0;
    std::map<int, int> distribution;
};

class AnalysisUtils {
public:
    /**
     * Hitung statistik bobot kolom H matrix
     */
    static WeightStats compute_h_weight_stats(const std::vector<pvac::BitVec>& H) {
        WeightStats stats;
        std::vector<int> weights;

        for (const auto& col : H) {
            int ones = 0;
            for (uint64_t w : col.w) {
                ones += __builtin_popcountll(w);
            }
            weights.push_back(ones);
            stats.distribution[ones]++;
        }

        if (weights.empty()) return stats;

        stats.min_weight = *std::min_element(weights.begin(), weights.end());
        stats.max_weight = *std::max_element(weights.begin(), weights.end());
        stats.avg_weight = std::accumulate(weights.begin(), weights.end(), 0.0) / weights.size();

        // Median
        std::vector<int> sorted_weights = weights;
        std::sort(sorted_weights.begin(), sorted_weights.end());
        if (sorted_weights.size() % 2 == 0) {
            stats.median_weight = (sorted_weights[sorted_weights.size() / 2 - 1] +
                                 sorted_weights[sorted_weights.size() / 2]) / 2.0;
        } else {
            stats.median_weight = sorted_weights[sorted_weights.size() / 2];
        }

        // Standard deviation
        double variance = 0.0;
        for (int w : weights) {
            variance += (w - stats.avg_weight) * (w - stats.avg_weight);
        }
        variance /= weights.size();
        stats.std_dev = std::sqrt(variance);

        return stats;
    }

    /**
     * Hitung paritas kolom H matrix
     */
    static std::pair<int, int> compute_h_parity(
        const std::vector<pvac::BitVec>& H
    ) {
        int even_count = 0, odd_count = 0;

        for (const auto& col : H) {
            int ones = 0;
            for (uint64_t w : col.w) {
                ones += __builtin_popcountll(w);
            }
            if (ones & 1) {
                odd_count++;
            } else {
                even_count++;
            }
        }

        return {even_count, odd_count};
    }

    /**
     * Hitung edge weight statistics untuk ciphertext
     */
    static WeightStats compute_edge_weight_stats(
        const pvac::Cipher& cipher
    ) {
        WeightStats stats;
        std::vector<int> weights;

        for (const auto& edge : cipher.E) {
            if (edge.w.empty()) continue;

            // Count non-zero weights
            int nonzero = 0;
            for (const auto& w : edge.w) {
                if (w.lo != 0 || w.hi != 0) nonzero++;
            }
            weights.push_back(nonzero);
            stats.distribution[nonzero]++;
        }

        if (weights.empty()) return stats;

        stats.min_weight = *std::min_element(weights.begin(), weights.end());
        stats.max_weight = *std::max_element(weights.begin(), weights.end());
        stats.avg_weight = std::accumulate(weights.begin(), weights.end(), 0.0) / weights.size();

        // Median
        std::vector<int> sorted_weights = weights;
        std::sort(sorted_weights.begin(), sorted_weights.end());
        if (sorted_weights.size() % 2 == 0) {
            stats.median_weight = (sorted_weights[sorted_weights.size() / 2 - 1] +
                                 sorted_weights[sorted_weights.size() / 2]) / 2.0;
        } else {
            stats.median_weight = sorted_weights[sorted_weights.size() / 2];
        }

        return stats;
    }

    /**
     * Deteksi kolom duplikat dalam H matrix
     */
    static std::vector<std::pair<size_t, size_t>> find_duplicate_columns(
        const std::vector<pvac::BitVec>& H
    ) {
        std::vector<std::pair<size_t, size_t>> duplicates;

        for (size_t i = 0; i < H.size(); ++i) {
            for (size_t j = i + 1; j < H.size(); ++j) {
                if (H[i].w == H[j].w) {
                    duplicates.push_back({i, j});
                }
            }
        }

        return duplicates;
    }

    /**
     * Analisa syndrome weight distribution
     */
    static WeightStats compute_syndrome_weight_stats(
        const std::vector<pvac::Edge>& edges
    ) {
        WeightStats stats;
        std::vector<int> weights;

        for (const auto& edge : edges) {
            if (edge.s.w.empty()) continue;

            int ones = 0;
            for (uint64_t w : edge.s.w) {
                ones += __builtin_popcountll(w);
            }
            weights.push_back(ones);
            stats.distribution[ones]++;
        }

        if (weights.empty()) return stats;

        stats.min_weight = *std::min_element(weights.begin(), weights.end());
        stats.max_weight = *std::max_element(weights.begin(), weights.end());
        stats.avg_weight = std::accumulate(weights.begin(), weights.end(), 0.0) / weights.size();

        // Median
        std::vector<int> sorted_weights = weights;
        std::sort(sorted_weights.begin(), sorted_weights.end());
        if (sorted_weights.size() % 2 == 0) {
            stats.median_weight = (sorted_weights[sorted_weights.size() / 2 - 1] +
                                 sorted_weights[sorted_weights.size() / 2]) / 2.0;
        } else {
            stats.median_weight = sorted_weights[sorted_weights.size() / 2];
        }

        return stats;
    }
};

} // namespace hfhe_tools
