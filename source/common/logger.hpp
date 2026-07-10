#pragma once

#include <iostream>
#include <string>
#include <ctime>
#include <iomanip>

namespace hfhe_tools {

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    CRITICAL = 4
};

class Logger {
private:
    LogLevel level = LogLevel::INFO;
    bool use_colors = true;
    bool use_timestamps = true;

    std::string get_timestamp() const {
        auto now = std::time(nullptr);
        auto tm = *std::localtime(&now);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    std::string level_to_string(LogLevel lvl) const {
        switch (lvl) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO: return "INFO";
            case LogLevel::WARN: return "WARN";
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::CRITICAL: return "CRITICAL";
            default: return "UNKNOWN";
        }
    }

    std::string get_color_code(LogLevel lvl) const {
        if (!use_colors) return "";
        switch (lvl) {
            case LogLevel::DEBUG: return "\033[36m";      // Cyan
            case LogLevel::INFO: return "\033[32m";       // Green
            case LogLevel::WARN: return "\033[33m";       // Yellow
            case LogLevel::ERROR: return "\033[31m";      // Red
            case LogLevel::CRITICAL: return "\033[1;31m"; // Bold Red
            default: return "";
        }
    }

    std::string get_reset_code() const {
        return use_colors ? "\033[0m" : "";
    }

public:
    Logger() = default;

    void set_level(LogLevel lvl) { level = lvl; }
    void disable_colors() { use_colors = false; }
    void disable_timestamps() { use_timestamps = false; }

    void log(LogLevel lvl, const std::string& msg) {
        if (static_cast<int>(lvl) < static_cast<int>(level)) return;

        std::string prefix;
        if (use_timestamps) {
            prefix += "[" + get_timestamp() + "] ";
        }
        prefix += "[" + level_to_string(lvl) + "] ";

        std::string color = get_color_code(lvl);
        std::string reset = get_reset_code();

        std::cerr << color << prefix << msg << reset << "\n";
    }

    void debug(const std::string& msg) { log(LogLevel::DEBUG, msg); }
    void info(const std::string& msg) { log(LogLevel::INFO, msg); }
    void warn(const std::string& msg) { log(LogLevel::WARN, msg); }
    void error(const std::string& msg) { log(LogLevel::ERROR, msg); }
    void critical(const std::string& msg) { log(LogLevel::CRITICAL, msg); }
};

static Logger g_logger;

inline Logger& get_logger() {
    return g_logger;
}

} // namespace hfhe_tools
