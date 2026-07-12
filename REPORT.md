# HFHE v2 Cryptanalysis — Exhaustive Attack Report

**Status: UNDEFEATED — No path to plaintext recovery found with current public techniques.**

## Summary

After exhaustive cryptanalysis spanning 40+ attack tests across every known category, the HFHE v2 challenge remains unbroken. Found and fixed a critical S-box CNF encoding bug in our AES-256 SAT solver. All LPN approaches hit the ~50% error wall. Independent security assessment (smoke-ui) also negative. Deep mathematical research confirms no exploitable structure.

## Attack Results

### LPN(4096, 1/8) — 15+ approaches, ALL negative

| Approach | Result | Details |
|----------|--------|---------|
| Gaussian elimination | ❌ 50% error | Noise corrupts completely |
| Bit-flipping | ❌ Stuck at 50% | No gradient landscape |
| Majority vote (44 instances) | ❌ 50% | 33/44 matrices singular |
| Integer correlation | ❌ No signal | Gap 482 vs 360,448 expected |
| Walsh-Hadamard | ❌ Infeasible | Requires 2^4096 evaluations |
| Simulated annealing | ❌ Stuck at 50% | Local optima trap |
| BKW/coded-BKW | ❌ Signal vanishes | After 16 stages, bias ~0.01 |
| BKZ lattice | ❌ Infeasible | Dimension ~4000 needed |
| LPN-SAT (CryptoMiniSat) | ❌ Timed out | 4096 equations too large |
| XL/Gröbner basis | ❌ 8.4M monomials | Degree-2 infeasible |
| ISD/syndrome decoding | ❌ 2^918+ | Dense random code |
| Neural network | ❌ Only n=26 | Doesn't scale to 4096 |
| WHT (k=15 bits) | ❌ No signal | Per-bit correlation = 0 |
| Weighted correlation | ❌ Zero signal | Mathematically proven |
| Multi-instance aggregation | ❌ No advantage | 720K samples insufficient |

**Mathematical proof**: For LPN y = ⟨A, s⟩ + e over GF(2), per-column correlation (2y-1)(2A[j]-1) has expectation = 0 for ALL s[j] values. The mod-2 structure destroys all per-bit signal. Only global optimization over 4096 binary variables can recover s.

### AES-256 SAT — Correct encoding, no convergence

- **Found critical S-box encoding bug**: Original truth-table encoding created 1 clause per input value (16 literals OR'd). Fixed to 8 separate clauses per value (one per output bit).
- **Verified with FIPS-197**: Key=0 → CT=dc95c078a2408989ad48a21492842087 ✓
- **CryptoMiniSat**: 29,159 vars, 1.1M clauses, ran 69 minutes without convergence
- **Z3 SMT**: S-box if-then-else chains make it even slower than CNF
- **Conclusion**: AES-256 is beyond SAT/SMT solver capability

### Ciphertext Analysis — No structural leaks

- 22 ciphers, 2 layers each, all c0=0
- Public T values match LPN sample headers exactly
- R₀≠R₁ across ciphers (different seeds, confirmed by cross-cipher test)
- Smooth Mersenne prime (p-1 has factors up to 2^23) — DLP trivial but useless
- Quotient group analysis: 44/44 unique signatures, 0 character zeros
- Signal decomposition: K=8 edges, 7 random + 1 deterministic (hidden by R)

### OSINT — Plaintext never leaked

- plaintext.txt NEVER committed to any repo (checked all 28 forks)
- No public hints about format on Twitter, Discord, Telegram, or forums
- No paste site leaks found
- Bounty wallet: 500,001 OCT, nonce 0 (never accessed)
- Creator (@lambda0xE) active but hasn't posted format hints

## Key Mathematical Insight

The challenge has TWO independent secrets:
1. **prf_k** (256 bits) — needed for R computation via AES-CTR + Toeplitz PRF
2. **lpn_s_bits** (4096 bits) — needed for LPN solving

Solving LPN gives s but NOT prf_k. Recovering prf_k requires breaking AES-256 or SHA-256. The wrapped encoding makes plaintext recovery information-theoretically impossible from public data alone (proven by smoke-ui with exhaustive verification in F_31).

## S-box Encoding Bug (Critical Fix)

The original truth-table encoding created ONE clause per input value:
```
¬in[0] ∨ ¬in[1] ∨ ... ∨ ¬in[7] ∨ out[0] ∨ out[1] ∨ ... ∨ out[7]
```
**Fix**: 8 SEPARATE clauses per input value:
```
¬in=val ∨ out_bit_k = sbox[val]_bit_k   (for each k=0..7)
```
Total: 2048 clauses per S-box, 1.1M clauses for full AES-256.

## Files

| File | Description |
|------|-------------|
| `REPORT.md` | Full technical report (253 lines) |
| `ANALYSIS.md` | Initial security analysis |
| `LPN_ANALYSIS.md` | LPN attack documentation (12 attempts) |
| `aes_full_sat.py` | AES-256 CNF encoder with corrected S-box |
| `ct_analyze.py` | Ciphertext parser and T-value computation |
| `source/tools/verify_lpn_sample_binding.cpp` | Binding verification |
| 40+ C++ tools | LPN solvers, correlation attacks, structural analysis |

## External References

- Independent assessment: smoke-ui/octra-hfhe-v2-security-assessment (14 attack classes, all negative)
- Aggarwal et al. 2026: "Towards Worst-case Hardness for Low-Noise LPN" — confirms LPN hardness
- Shiu et al. 2026: "Spectral Method attacks Sparse LWE, Sparse LPN" — only for sparse, not dense
- V1 solver: Iamknownasfesal/octra-hfhe-challenge-recovery (uses revealed sk)
- PR #2 (empty, self-closed by author), PR #4 (attack tools, self-closed by author)
- No public claims of solution as of July 12, 2026

## What Would Be Needed

1. Novel LPN solving technique for n=4096, τ=1/8 (best known: 2^300+ ops)
2. AES-256 cryptanalysis breakthrough (best SAT: ~8 rounds)
3. Structural vulnerability not found in audit
4. Side information from creator

---

*Report generated 2026-07-12. All code and data available in this repository.*
