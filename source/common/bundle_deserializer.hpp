#pragma once

#include <pvac/pvac.hpp>
#include "pvac_artifact_serialize.hpp"
#include "logger.hpp"

#include <vector>
#include <cstring>
#include <array>
#include <stdexcept>
#include <sstream>

namespace hfhe_tools {

struct BundleStats {
    size_t total_bytes = 0;
    uint64_t cipher_count = 0;
    size_t successfully_deserialized = 0;
    size_t deserialization_failures = 0;
    std::vector<std::string> error_messages;
};

class BundleDeserializer {
private:
    static constexpr std::array<uint8_t, 16> BUNDLE_MAGIC = {
        'O','C','T','R','A','-','H','F','H','E','-','B','T','Y','0','2'
    };
    static constexpr uint64_t MAX_CIPHER_COUNT = 1024;

public:
    /**
     * Validasi magic number bundle
     */
    static bool validate_magic(const std::vector<uint8_t>& data) {
        if (data.size() < BUNDLE_MAGIC.size()) {
            return false;
        }
        return std::equal(BUNDLE_MAGIC.begin(), BUNDLE_MAGIC.end(), data.begin());
    }

    /**
     * Parse header bundle untuk mendapatkan cipher count
     */
    static uint64_t get_cipher_count(const std::vector<uint8_t>& data) {
        if (data.size() < 24) {
            throw std::runtime_error("bundle: data too small for header");
        }

        if (!validate_magic(data)) {
            throw std::runtime_error("bundle: invalid magic number");
        }

        uint64_t count = 0;
        std::memcpy(&count, &data[16], 8);

        if (count == 0) {
            throw std::runtime_error("bundle: cipher count is zero");
        }

        if (count > MAX_CIPHER_COUNT) {
            throw std::runtime_error("bundle: cipher count exceeds maximum (" +
                                   std::to_string(count) + " > " +
                                   std::to_string(MAX_CIPHER_COUNT) + ")");
        }

        return count;
    }

    /**
     * Deserialize bundle dengan error handling granular
     * @param data Bundle data bytes
     * @param stats Output statistics (optional)
     * @return Vector of deserialized ciphers
     * @throw std::runtime_error jika bundle structure invalid
     */
    static std::vector<pvac::Cipher> deserialize_bundle_strict(
        const std::vector<uint8_t>& data,
        BundleStats* stats = nullptr
    ) {
        auto& logger = get_logger();

        BundleStats local_stats;
        if (stats == nullptr) stats = &local_stats;
        stats->total_bytes = data.size();

        // Validate magic
        if (!validate_magic(data)) {
            std::string err = "bundle: invalid magic number";
            logger.error(err);
            throw std::runtime_error(err);
        }

        // Get cipher count
        uint64_t cipher_count = get_cipher_count(data);
        stats->cipher_count = cipher_count;
        logger.debug("Bundle has " + std::to_string(cipher_count) + " ciphers");

        // Parse ciphers
        size_t pos = 24;
        std::vector<pvac::Cipher> ciphers;
        ciphers.reserve(static_cast<size_t>(cipher_count));

        for (uint64_t i = 0; i < cipher_count; ++i) {
            // Check if we have space for length field
            if (pos + 8 > data.size()) {
                std::string err = "bundle: truncated at cipher " + std::to_string(i) +
                                 " (no space for length field)";
                logger.error(err);
                stats->deserialization_failures++;
                stats->error_messages.push_back(err);
                break;
            }

            // Read cipher length
            uint64_t ct_len = 0;
            std::memcpy(&ct_len, &data[pos], 8);
            pos += 8;

            // Validate cipher length
            if (ct_len == 0) {
                std::string err = "bundle: cipher " + std::to_string(i) +
                                 " has zero length";
                logger.warn(err);
                stats->deserialization_failures++;
                stats->error_messages.push_back(err);
                continue;
            }

            if (ct_len > data.size() - pos) {
                std::string err = "bundle: cipher " + std::to_string(i) +
                                 " length exceeds remaining data (" +
                                 std::to_string(ct_len) + " > " +
                                 std::to_string(data.size() - pos) + ")";
                logger.error(err);
                stats->deserialization_failures++;
                stats->error_messages.push_back(err);
                break;
            }

            // Deserialize cipher
            try {
                pvac::Cipher c = pvac_ser::deserialize_cipher(&data[pos], static_cast<size_t>(ct_len));
                ciphers.push_back(c);
                stats->successfully_deserialized++;
                logger.debug("Deserialized cipher " + std::to_string(i) +
                           " (" + std::to_string(ct_len) + " bytes, " +
                           std::to_string(c.E.size()) + " edges)");
            } catch (const std::exception& e) {
                std::string err = "bundle: cipher " + std::to_string(i) +
                                 " deserialization failed: " + std::string(e.what());
                logger.error(err);
                stats->deserialization_failures++;
                stats->error_messages.push_back(err);
            }

            pos += static_cast<size_t>(ct_len);
        }

        // Check for trailing bytes
        if (pos != data.size()) {
            std::string warn = "bundle: " + std::to_string(data.size() - pos) +
                              " trailing bytes after last cipher";
            logger.warn(warn);
        }

        if (stats->successfully_deserialized == 0) {
            throw std::runtime_error("bundle: no ciphers deserialized successfully");
        }

        logger.info("Bundle deserialization complete: " +
                   std::to_string(stats->successfully_deserialized) + "/" +
                   std::to_string(stats->cipher_count) + " ciphers");

        return ciphers;
    }

    /**
     * Legacy version untuk compatibility
     */
    static std::vector<pvac::Cipher> deserialize_bundle(
        const std::vector<uint8_t>& data
    ) {
        return deserialize_bundle_strict(data);
    }
};

} // namespace hfhe_tools
