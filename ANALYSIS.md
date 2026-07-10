# HFHE Challenge v2 — Cryptanalysis Notes

Working notes on Octra's HFHE (`pvac_hfhe_cpp` @ `071b0e9`) bounty v2.
Goal: recover the plaintext of `secret.ct` (a wallet private key + metadata for
`octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`) from public files only.

## Scheme overview

- Field `F_p`, `p = 2^127 - 1`. Basis `powg_B[i] = g^i`, `i in [0,B)`, `B = 337`,
  where `g` has multiplicative order 337 (a small subgroup).
- A value `v in F_p` is encrypted as a set of **edges**. Each edge = `(layer_id,
  idx, sign, w, sigma)`. `w` is a field weight, `sigma = H*x xor e` is an LPN/H
  syndrome used only by the recrypt proof system (**ignored during decryption**).
- Decryption identity (`ops/decrypt.hpp`):

  ```
  v = c0 + sum_edges  sign * w * g^idx * R^{-1}[layer]
  ```

  `R[layer]` is a secret per-layer **multiplicative mask**:
  `R = prf_R(sk, seed) = r1*r2*r3`, each `ri = Toeplitz127(LPN_syndrome(sk, seed, dom_i))`.
  Seeds `(ztag, nonce)` are public; `R` depends on the secret key `sk`
  (`sk.prf_k[4]`, `sk.lpn_s_bits` = 4096-bit LPN secret).
- Text (`utils/text.hpp`): message split into 15-byte blocks, each packed into an
  `Fp`. Cipher 0 encrypts the byte length; ciphers 1..k encrypt the blocks.
  `secret.ct` = **22 ciphers** => 1 length + 21 blocks = up to **315 bytes**.
- **v2 "wrapped" encoding** (`enc_fp_wrapped_depth`): each block is
  `fuse(Enc(v+m), Enc(-m))` with a fresh uniform `m` and **two independent BASE
  layers**, i.e. two independent masks `R0`, `R1`.

## The only public plaintext-dependent quantity

Every edge weight has the form `w = R * c`. Summing a layer's edges gives a
publicly computable invariant:

```
T_L := sum_{e in L} sign * w * g^idx  =  target_L * R_L
```

For a wrapped block:  `T0 = (v+m) * R0`,  `T1 = (-m) * R1`.

`R0, R1, m` are **independent and uniform** (`getrandom`). Therefore `(T0, T1)` is
uniform over `(F_p*)^2` **independently of `v`**: for every observed pair and
every candidate `v` there is exactly one `R1` that fits, so `v` is uniform given
the public data. **This is information-theoretic hiding, not merely computational.**

## Known plaintext analysis

Three ciphers have fully known plaintext blocks:
- Cipher 0: `v = 110` (text byte length)
- Cipher 1: `v = pack("email = bounty.")` (first text block)
- Cipher 3: `v = pack("a.org\nsecret = ")` (fourth text block)

For each known `v`: `T0/(v+m) = R0` and `T1/(-m) = R1`. But `m` is uniform and
independent, so `R0` and `R1` are not recoverable. The constraint `T0/R0 + T1/R1 = v`
is satisfied for ALL `v` with appropriate `(R0, R1, m)`.

## Attack surfaces evaluated (all negative at `071b0e9`)

| # | Avenue | Result |
| --- | --- | --- |
| 1 | v1 `R_com` commitment oracle | **Removed** — computed but not serialized (`write_layer`). |
| 2 | Weak / seedable PRNG | **No** — masks/`m`/coeffs from `getrandom()` (`core/random.hpp`). |
| 3 | `w` clustering / duplicate indices | **No** — `merge()` collapses duplicates; every `w = R*uniform` is uniform. |
| 4 | Linear / ratio / projection to cancel `R` | **No** — no edge weight is a known multiple of `R`. |
| 5 | `sigma` / parity leakage | **No** — `sigma` ignored at decrypt; random `H`-syndromes. |
| 6 | `pk` leaks `sk` | **No** — `keygen()` samples independently. |
| 7 | Statistical bias in `R` / weights | **No** — `R = r1*r2*r3` (hash-to-field), `w` uniform; no observed bias. |
| 8 | LPN cryptanalysis | **No observable instance** — matrix and syndrome both secret. |
| 9 | Wrapped-pair addition leak | **No** — independent masks `R0 != R1`. |
| 10 | Cross-cipher mask reuse | **No** — all 44 seeds distinct (verified). |
| 11 | Candidate verification via format | **Impossible** — every `v` equally consistent. |
| 12 | Subgroup structure of `g` | **No** — multiplicative only, no linear leverage. |
| 13 | Pedersen PC leaks R⁻¹ | **No** — blinding derived from secret `prf_k`. |
| 14 | Cross-layer AES key correlation | **No** — seeds random, T values uniform. |

## Empirical results

### Seed analysis
All 44 layer seeds are random 192-bit values with no pattern. Seed differences
within ciphers are uniformly distributed.

### T value analysis
T0/T1 ratios, T0*T1 products, and T0+T1 sums are all uniformly distributed
across ciphers. No distinguishable pattern between known-plaintext and
unknown-plaintext ciphers.

### Known-plaintext distinguisher
Encrypting blocks of `v=0` vs known nonzero values produces identical statistics:
```
v=0    : meanU(T0)=0.4999 meanU(T1)=0.5038 avgEdges=47.3
v=known: meanU(T0)=0.4895 meanU(T1)=0.4754 avgEdges=47.4
```
No public distinguisher separates the two classes.

## The LPN barrier

The mask PRF `R = prf_R(sk, seed)` uses LPN internally:
- `y_r = <A_r, s> XOR e_r` with `k=4096`, `t=16384`, `tau=1/8`
- Matrix `A` is AES-CTR keyed by `sk.prf_k` — **not public**
- Syndrome `y` is consumed by Toeplitz compression — **never serialized**
- `R` itself is never public, only `T = v*R`

**Exposed LPN equations: 0.** No solver can be instantiated.

Even if the LPN instance were fully exposed:
- Gauss/ISD: ~2^789 operations
- BKW: ~2^341 operations  
- Best known asymptotic: >2^128 for k≥512, tau=1/8

## Cross-cipher correlation analysis

All 22 ciphers share the same `sk.lpn_s_bits` (4096-bit LPN secret). However:
- Each layer uses a different AES key (derived from different seed)
- The AES key includes `seed.ztag` and `seed.nonce` which are random per layer
- The LPN matrix `A` and noise `e` are independently generated per layer
- The Toeplitz compression keys are independently derived per layer

**Result:** The `y` vectors across layers are computationally independent. No
cross-cipher correlation is observable without knowing `sk.prf_k`.

## Conclusion

Recovering the plaintext from public files reduces to inverting the LPN-based mask
PRF (recover `sk.lpn_s_bits` / `sk.prf_k`). The LPN instance is used purely as
an internal PRF whose per-call outputs are never observable. No oracle, bias,
weak-RNG, algebraic linearity, or `pk→sk` leak was found. The v2 scheme is
**information-theoretically hiding** per cipher and **computationally secure**
across ciphers under LPN assumptions.

The only published break (v1, wallet `oct6Y7j...`) used an `R_com` oracle that v2
removes. The v2 target remains unsolved.

## Tools

- `tools/probe.cpp` — recompute `T_L` for all layers of `secret.ct`
- `tools/lpn_estimate.py` — LPN hardness estimates
- `tools/cross_layer.cpp` — cross-layer seed and T-value analysis

## Build & run

```bash
# Requires pvac_hfhe_cpp @ 071b0e9 checked out adjacent
g++ -std=c++17 -O2 -march=native -maes \
    -Ipvac_hfhe_cpp/include -Isource tools/probe.cpp -o probe
./probe .
```

## References

- [pvac_hfhe_cpp](https://github.com/octra-labs/pvac_hfhe_cpp) @ `071b0e9`
- [hfhe-challenge](https://github.com/octra-labs/hfhe-challenge)
- [v1 recovery (different wallet)](https://github.com/Iamknownasfesal/octra-hfhe-challenge-recovery)
- [HFHE docs](https://docs.octra.org/technology/hfhe)
