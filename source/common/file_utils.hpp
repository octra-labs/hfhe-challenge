#pragma once

#include <fstream>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include "logger.hpp"

namespace hfhe_tools {

class FileUtils {
public:
    // Maximum file size: 1 GB
    static constexpr size_t MAX_FILE_SIZE = 1ULL << 30;

    /**
     * Luka file dengan error handling ketat
     * @param path Path ke file
     * @param max_size Ukuran maksimal yang diizinkan (default: MAX_FILE_SIZE)
     * @return Vector berisi byte file
     * @throw std::runtime_error jika file tidak dapat dibuka atau terlalu besar
     */
    static std::vector<uint8_t> read_file_strict(
        const std::string& path,
        size_t max_size = MAX_FILE_SIZE
    ) {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            auto& logger = get_logger();
            logger.error("Cannot open file: " + path);
            throw std::runtime_error("Cannot open file: " + path);
        }

        // Get file size
        file.seekg(0, std::ios::end);
        if (!file.good()) {
            auto& logger = get_logger();
            logger.error("Cannot seek to end: " + path);
            throw std::runtime_error("Cannot seek to end: " + path);
        }

        std::streampos size_pos = file.tellg();
        if (size_pos < 0) {
            auto& logger = get_logger();
            logger.error("Cannot determine file size: " + path);
            throw std::runtime_error("Cannot determine file size: " + path);
        }

        size_t file_size = static_cast<size_t>(size_pos);

        // Check size limits
        if (file_size == 0) {
            auto& logger = get_logger();
            logger.warn("File is empty: " + path);
        }

        if (file_size > max_size) {
            auto& logger = get_logger();
            logger.error("File too large: " + path + " (" + std::to_string(file_size) +
                        " > " + std::to_string(max_size) + " bytes)");
            throw std::runtime_error("File too large: " + path);
        }

        // Read file
        file.seekg(0, std::ios::beg);
        if (!file.good()) {
            auto& logger = get_logger();
            logger.error("Cannot seek to begin: " + path);
            throw std::runtime_error("Cannot seek to begin: " + path);
        }

        std::vector<uint8_t> data(file_size);
        if (file_size > 0) {
            file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(file_size));
            if (!file) {
                auto& logger = get_logger();
                logger.error("Cannot read file: " + path);
                throw std::runtime_error("Cannot read file: " + path);
            }
        }

        auto& logger = get_logger();
        logger.debug("Read file: " + path + " (" + std::to_string(file_size) + " bytes)");
        return data;
    }

    /**
     * Legacy version untuk compatibility
     */
    static std::vector<uint8_t> read_file(const std::string& path) {
        return read_file_strict(path);
    }

    /**
     * Tulis file dengan error handling
     */
    static void write_file(
        const std::string& path,
        const std::vector<uint8_t>& data
    ) {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            auto& logger = get_logger();
            logger.error("Cannot open file for writing: " + path);
            throw std::runtime_error("Cannot open file for writing: " + path);
        }

        if (!data.empty()) {
            file.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
            if (!file) {
                auto& logger = get_logger();
                logger.error("Cannot write file: " + path);
                throw std::runtime_error("Cannot write file: " + path);
            }
        }

        file.close();
        auto& logger = get_logger();
        logger.debug("Wrote file: " + path + " (" + std::to_string(data.size()) + " bytes)");
    }

    /**
     * Check if file exists
     */
    static bool file_exists(const std::string& path) {
        struct stat buffer;
        return (stat(path.c_str(), &buffer) == 0);
    }

    /**
     * Get file size
     */
    static size_t get_file_size(const std::string& path) {
        struct stat buffer;
        if (stat(path.c_str(), &buffer) != 0) {
            throw std::runtime_error("Cannot stat file: " + path);
        }
        return static_cast<size_t>(buffer.st_size);
    }
};

} // namespace hfhe_tools
