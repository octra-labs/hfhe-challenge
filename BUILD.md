# Building the HFHE Challenge Solver

## Prerequisites

1. **PVAC-HFHE library** (commit: 071b0e909c119de815e284b347c4bd979cb59ef3)
   ```bash
   git clone https://github.com/octra-labs/pvac_hfhe_cpp.git
   cd pvac_hfhe_cpp
   git checkout 071b0e9
   # Build according to their instructions
   ```

2. **C++17 compiler** (GCC 9+, Clang 10+, or MSVC 2019+)

3. **CMake 3.15+**

4. **nlohmann/json** library (header-only)
   ```bash
   wget https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp
   # Place in appropriate include path
   ```

## Build Instructions

### Option 1: Using CMake (Recommended)

```bash
cd hfhe-challenge
mkdir build
cd build
cmake .. -DPVAC_HFHE_ROOT=/path/to/pvac_hfhe_cpp -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Option 2: Manual Compilation

```bash
cd hfhe-challenge/tools

# Challenge Analyzer
g++ -std=c++17 -O3 -march=native \
  -I/path/to/pvac_hfhe_cpp/include \
  -I../source \
  challenge_analyzer.cpp -o challenge-analyzer

# Plaintext Recovery
g++ -std=c++17 -O3 -march=native \
  -I/path/to/pvac_hfhe_cpp/include \
  -I../source \
  plaintext_recovery.cpp -o plaintext-recovery

# Public Key Analysis
g++ -std=c++17 -O3 -march=native \
  -I/path/to/pvac_hfhe_cpp/include \
  -I../source \
  attack_pubkey_analysis.cpp -o attack-pubkey

# Syndrome Decoder
g++ -std=c++17 -O3 -march=native \
  -I/path/to/pvac_hfhe_cpp/include \
  -I../source \
  attack_syndrome_decoder.cpp -o attack-syndrome

# Inspect Artifacts
g++ -std=c++17 -O3 -march=native \
  -I/path/to/pvac_hfhe_cpp/include \
  -I../source \
  inspect_artifacts.cpp -o inspect-artifacts
```

## Usage

### 1. Analyze Challenge Structure
```bash
./challenge-analyzer
```
Provides overview of public key, ciphertext structure, and potential vulnerabilities.

### 2. Inspect Binary Artifacts
```bash
./inspect-artifacts pk         # Inspect public key
./inspect-artifacts ct         # Inspect ciphertext
./inspect-artifacts params     # Show params.json
```

### 3. Plaintext Recovery Attempt
```bash
./plaintext-recovery
```
Attempts to recover plaintext using various attack vectors.

### 4. Public Key Analysis
```bash
./attack-pubkey
```
Analyzes H matrix structure, UBK, and potential weaknesses.

### 5. Syndrome Decoder Analysis
```bash
./attack-syndrome
```
Analyzes syndrome structure and LPN decoding surface.

## Troubleshooting

### "Cannot find pvac/pvac.hpp"
- Set `PVAC_HFHE_ROOT` to the root directory of the pvac_hfhe_cpp repository
- Ensure pvac_hfhe_cpp is built: `make test-hfhe-native` should work

### "nlohmann/json not found"
- Download json.hpp header from GitHub
- Place in `/usr/local/include/nlohmann/` or add to CMakeLists.txt

### Compilation fails with "undefined reference"
- Some PVAC functions may need to be compiled from source
- Check if pvac_hfhe_cpp has prebuilt objects or requires building
- May need to link against compiled PVAC objects if they exist

## Attack Strategy

The tools focus on two main attack vectors:

1. **Structural Analysis**: Find weaknesses in the H matrix, UBK permutation, or layer structure
2. **Syndrome Decoding**: Exploit the LPN problem via syndrome analysis
3. **Information Leakage**: Analyze the public portion (c0 slot[0]) for data leaks
4. **Parameter Exploitation**: Check for weak parameter choices

For detailed progress, check tool output and modify the C++ code to implement specific attack strategies.
