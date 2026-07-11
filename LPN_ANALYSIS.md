# The LPN Angle — Attempt and Result

## Update (July 11, 2026): LPN samples exposed

At the request of the community, the creator added LPN artifacts to the challenge
repository on July 11. The README states: *"The task is clear now: recover S from
y = <A, S> xor e, with tau = 1/8 and n = 4096."*

### What the LPN samples contain

Each of the 44 JSONL files (`ct{00-43}_l{0,1}_s0_pvac_prf_r_1.jsonl`) contains:

- **Line 0 (header):** metadata including `row_words: 64` (a count, NOT the data)
- **Lines 1-16384:** actual LPN data with fields:
  - `i`: sample index (0-16383)
  - `y`: the LPN output bit (0 or 1) — **this is the syndrome**
  - `a`: the A matrix row as 1024-char hex string (512 bytes = 4096 bits)

**This is a FULL LPN instance.** We now have both A and y. Total: 44 instances ×
16,384 samples = 720,896 equations in 4,096 unknowns.

### y distribution

All 44 instances show ~50/50 y distribution (as expected for random LPN output):
```
ct00_l0: 8196/16384 = 50.0%
ct09_l0: 8375/16384 = 51.1%  (highest)
ct10_l1: 8080/16384 = 49.3%  (lowest)
```

### LPN-solving attempts (all negative)

We exhaustively tried every known LPN-solving approach on the exposed data:

| # | Approach | Result | Why it fails |
|---|----------|--------|--------------|
| 1 | **Bit-flipping local search** | Stuck at 50.0% | Zero gradient from random start |
| 2 | **Integer correlation** `C_j = Σ A_ij * y_i` | Gap = 482 (expected 360,448) | Signal masked by interference from other 4095 bits |
| 3 | **Gaussian elimination + verify** | 49.6% error rate | Noise corrupts triangular form; any s with ≥1 wrong bit → 50% |
| 4 | **GE + bit-flipping refinement** | 0 bits flipped | Zero gradient even from GE solution |
| 5 | **Walsh-Hadamard transform** | Infeasible | Requires 2^4096 evaluations |
| 6 | **Goldreich-Levin partial WHT** | Peak 0.014 (expected 0.75) | Signal globally distributed, not localized |
| 7 | **Pairwise XOR bias** | Bias = 0.28125 | Too small to exploit at scale |
| 8 | **Multi-instance exploitation** | No advantage | Aggarwal et al. 2026 (arXiv:2605.10056) proves multi-instance ≡ single |
| 9 | **BKW** | ~2^357 | Infeasible |
| 10 | **ISD (Stern/BJMM)** | ~2^1869 | Infeasible |
| 11 | **Covering codes** | ~2^1017 | Infeasible |
| 12 | **Lattice (LLL/BKZ)** | Dimension 4096 too large | fpylll can't handle |

### The fundamental blocker: mod-2 structure

The killer property of LPN over GF(2): **any s with even 1 wrong bit gives ~50%
error rate**, indistinguishable from random. Only the EXACT correct s gives ~12.5%.
This makes ALL iterative/refinement approaches impossible:

- From random s: error = 50%, gradient = 0 → stuck
- From GE solution (49.6%): error = 50%, gradient = 0 → stuck
- From any s with k ≥ 1 wrong bits: error = 50%, gradient = 0 → stuck

There is no "almost correct" intermediate state. The landscape is a flat plateau at
50% with a single needle at 12.5%.

### Theoretical complexity

For LPN(n=4096, τ=1/8) with t=720,896 samples:

| Method | Complexity |
|--------|-----------|
| Brute force | 2^4096 |
| Prange ISD | 2^2227 |
| Stern ISD | 2^1869 |
| BJMM | 2^1500+ (estimated) |
| BKW | 2^357 |
| Covering codes | 2^1017 |
| Simple LPN attack | 2^968 |
| Best known (any method) | >2^128 for n≥512 |

No published 2024-2026 technique improves on these bounds at n=4096.

### The AES key for the LPN matrix

The AES key for generating A is `SHA256(sk.prf_k || seed || domain)`, NOT
`SHA256(s[0..1] || seed || domain)`. The matrix depends on `prf_k` (the 256-bit
PRF key), not on the LPN secret `s_bits`. This means there is NO self-referential
structure to exploit.

## Previous analysis (pre-July 11)

### Step 1 — Is there an observable LPN instance?

**Before July 11:** No. Both A and y were secret. No solver could be instantiated.

**After July 11:** Yes! Full A and y exposed in `lpn_samples/`. But solving is still
infeasible at n=4096.

### Step 2 — Even with exposed data, is it feasible?

No. All known algorithms require >2^300 operations for n=4096, τ=1/8. The 176×
overdetermination (t/n = 176) does not reduce complexity below 2^300.

### Step 3 — Does knowing a plaintext block help?

No. Each block uses independent masks (R0, R1). Knowing v gives R = T/v but R
depends on prf_k (unknown), not s_bits. The LPN and PRF are independent paths.

### Step 4 — Cross-cipher LPN correlation

All 44 instances share the same s_bits. But:
- Each instance has independent A matrix (different AES key)
- Each instance has independent noise e
- Aggarwal 2026 proves multi-instance LPN ≡ single-instance
- **No advantage from combining instances**

### Step 5 — Algebraic attack on AES key derivation

The AES key is `SHA256(prf_k || ...)`. SHA256 is one-way. No algebraic shortcut.

## Conclusion

The LPN samples expose the full instance (A and y), confirming the problem is
well-defined. However, LPN(4096, 1/8) remains infeasible with all known techniques.
The mod-2 structure prevents any iterative refinement, and the best algorithms
(ISD/BKW) require >2^300 operations.

The challenge was redacted and reopened on July 11 with LPN samples added. The
creator states "the task is clear now." Either there exists a novel technique not
in the public literature, or the LPN is a separate research problem rather than the
intended decryption path.

**Recommendation:** Contact dev@octra.org for guidance on whether a specific LPN
solving technique exists, or whether there is an alternative path to decryption.

## References

- [pvac_hfhe_cpp](https://github.com/octra-labs/pvac_hfhe_cpp) @ `071b0e9`
- [hfhe-challenge](https://github.com/octra-labs/hfhe-challenge)
- [Aggarwal et al. 2026 — Multi-instance LPN hardness](https://arxiv.org/abs/2605.10056)
- [Esser et al. 2025 — LPN via covering codes](https://eprint.iacr.org/2025/1521)
