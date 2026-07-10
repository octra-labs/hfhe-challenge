cmake_minimum_required(VERSION 3.15)
project(hfhe-challenge-solver CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -pthread")

if(NOT DEFINED PVAC_HFHE_ROOT)
    message(STATUS "PVAC_HFHE_ROOT not set, attempting to find...")
    find_package(pvac_hfhe QUIET)
    if(NOT pvac_hfhe_FOUND)
        message(FATAL_ERROR "Please set -DPVAC_HFHE_ROOT=/path/to/pvac_hfhe_cpp or install pvac_hfhe")
    endif()
else()
    message(STATUS "Using PVAC_HFHE_ROOT: ${PVAC_HFHE_ROOT}")
endif()

include_directories(${PVAC_HFHE_ROOT}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/source)

# Challenge Analyzer
add_executable(challenge-analyzer
    tools/challenge_analyzer.cpp
)

# Plaintext Recovery Tool
add_executable(plaintext-recovery
    tools/plaintext_recovery.cpp
)

# Attack: Public Key Analysis
add_executable(attack-pubkey
    tools/attack_pubkey_analysis.cpp
)

# Attack: Syndrome Decoder
add_executable(attack-syndrome
    tools/attack_syndrome_decoder.cpp
)

# Utility: Deserialize & Inspect
add_executable(inspect-artifacts
    tools/inspect_artifacts.cpp
)
