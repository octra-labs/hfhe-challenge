# HFHE Challenge v2 - Plaintext Recovery Guide

## Overview

This repository contains tools to analyze and attempt plaintext recovery for the HFHE Challenge v2.

**Challenge Goal**: Recover plaintext from `secret.ct` using only public artifacts (`pk.bin`, `params.json`).

## Challenge Parameters

From `params.json`:
- **Field**: Fp where p = 2^127 - 1 (127-bit prime)
- **Matrix H**: 8192 × 16384 (m_bits × n_bits)
- **H column weight**: 192
- **LPN parameters**: n=4096, t=16384
- **Error weight**: 128 bits
- **Encoding**: PVAC-HFHE v3

## Cryptographic System

PVAC-HFHE is based on:
- **LPN (Learning Parity with Noise)** problem
- **Hypergraph-based syndrome decoder** construction
- **Layered computation** for homomorphic operations

The system encrypts text using:
1. Generate random H (sparse m×n matrix over GF(2))
2. Create error vector e with low Hamming weight
3. Compute syndrome s = H·x + e (mod 2)
4. Encrypt plaintext by wrapping in polynomial layers

## Tools Included

### 1. challenge-analyzer
Provides high-level analysis of the challenge artifacts:
- Public key structure and parameters
- Ciphertext bundle format and layer structure
- Basic compatibility checks
- Public zero detection

```bash
./challenge-analyzer
```

### 2. inspect-artifacts
Detailed inspection of binary files:
```bash
./inspect-artifacts pk      # JSON output of public key structure
./inspect-artifacts ct      # Ciphertext bundle analysis
./inspect-artifacts params  # Show parameter file
```

### 3. plaintext-recovery
Attempts plaintext recovery using multiple attack vectors:
```bash
./plaintext-recovery
```

Tests:
- Public zero leakage detection
- H matrix parity analysis
- LPN parameter assessment

### 4. attack-pubkey
Focused analysis on public key weaknesses:
```bash
./attack-pubkey
```

Analyzes:
- H matrix weight distribution and anomalies
- UBK (Universal Basis Key) structure
- Column duplication (critical vulnerability)
- Parity structure irregularities

### 5. attack-syndrome
Syndrome structure analysis:
```bash
./attack-syndrome
```

Investigates:
- Syndrome weight statistics
- Layer dependency chains
- Edge weight patterns
- Bootstrapping issues

## Known Attack Vectors

### A1: Syndrome Decoding
The core security relies on the hardness of the LPN syndrome decoding problem:
- **Input**: H (public), syndrome s = H·x + e (computed from ciphertext)
- **Problem**: Recover x (private key) or e (error)
- **Complexity**: 2^(~60) for parameters here (theoretical)
- **Status**: No known polynomial-time algorithm

### A2: H Matrix Rank Analysis
If rank(H) < m_bits over GF(2):
- The system has dependencies
- Syndrome space is reduced
- May enable faster decoding

**Check**:
```cpp
// Gaussian elimination on H^T to compute rank
// If rank < 8192: potential vulnerability
```

### A3: Column Duplication
If H has duplicate columns:
- Two columns with same values collapse the space
- Creates immediate weakness

**Check**: `attack-pubkey` detects this

### A4: Parity Imbalance
If H columns have skewed parity distribution:
- Non-random structure
- May enable statistical attacks

**Check**: Look for parities not ~50% even/odd

### A5: Layer Dependency Exploitation
If PROD layers have structural issues:
- Bootstrapping might not amplify security
- Could enable feedback attacks

### A6: Edge Weight Patterns
Small weights in edge.w vectors:
- Direct computation advantages
- Potentially breaks FHE property

## Research Directions

### 1. Syndrome Decoding Algorithms
- Study Fast Walsh-Hadamard Transform (FWHT) attacks on LPN
- Analyze BKW (Blum-Kalai-Wasserman) algorithm applicability
- Check for weak parameter combinations

### 2. Algebraic Attacks
- Compute Gröbner basis of the system
- Analyze polynomial relations in ciphertext structure
- Look for degree-1 polynomials (linear system)

### 3. Information Leakage
- Analyze c0[0] (first slot) of ciphertexts
- Check for bias in Fp arithmetic results
- Look for side-channel patterns

### 4. Matrix Factorization
- Attempt to factor H over GF(2)
- Look for hidden structure (e.g., product form)
- Check for biased row/column sums

### 5. Lattice Reduction
- Formulate as CVP/SVP instance
- Use LLL/BKZ algorithms
- Analyze if dimension is tractable

## Development Workflow

1. **Run initial analysis**:
   ```bash
   ./challenge-analyzer        # Overview
   ./attack-pubkey            # Find weaknesses
   ```

2. **Based on findings, modify**:
   - `tools/plaintext_recovery.cpp` - add specific recovery logic
   - `tools/attack_*.cpp` - extend analysis
   - Add new `tools/custom_attack.cpp` - implement novel idea

3. **Rebuild and test**:
   ```bash
   cmake --build build -j$(nproc)
   ./build/plaintext-recovery
   ```

4. **Document findings** in `RESULTS.md`

## Important Notes

- The challenge uses commit `071b0e909c119de815e284b347c4bd979cb59ef3` of pvac_hfhe_cpp
- You MUST use this exact version for compatibility
- Plaintext is wrapped with "pvac-text-wrapped" encoding (see artifact code)
- Success requires recovering either:
  1. The private key (sk.bin)
  2. A direct cryptanalytic break
  3. Information leakage from the ciphertext

## References

- HFHE Challenge: https://github.com/nxpath/hfhe-challenge
- PVAC-HFHE Code: https://github.com/octra-labs/pvac_hfhe_cpp/tree/071b0e9
- LPN Problem: https://en.wikipedia.org/wiki/Learning_parity_with_noise
- Syndrome Decoding: [Finiasz & Sendrier 2009]

## Success Criteria

You win by:
1. Recovering plaintext from `secret.ct`
2. Demonstrating the plaintext decodes to valid instructions
3. Publishing your cryptanalytic method
4. Claiming the 500,000 OCT bounty

Good luck! 🚀
