# HFHE Challenge v2 — Cryptanalysis Notes

Working notes on Octra's HFHE (`pvac_hfhe_cpp` @ `071b0e9`) bounty v2.
Goal: recover the plaintext of `secret.ct` (a wallet private key + metadata for
`octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`) from public files only.

## Scheme in one page

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

Rigorously, a layer's published weight vector is uniform on the single affine
hyperplane `{ w : sum sign*w*g^idx = T_L }`; it reveals `T_L` and nothing else.
Nothing else in the artifact depends on the plaintext: seeds are random, `PC` is a
hiding Pedersen commitment to `R^{-1}`, `sigma` are random `H`-syndromes, `c0 = 0`.

`tools/probe.cpp` recomputes `T_L` for every layer of the real `secret.ct`.

## Attack surfaces evaluated (all negative at `071b0e9`)

| Avenue | Result |
| --- | --- |
| v1 `R_com` commitment oracle | **Removed** — `R_com` computed but not serialized (`write_layer`). |
| Weak / seedable PRNG | **No** — masks/`m`/coeffs from `getrandom()` (`core/random.hpp`). |
| `w` clustering / duplicate indices (old bugs) | **No** — `merge()` collapses duplicate `(layer,idx,sign)`; every `w = R*uniform` is uniform. |
| Linear / ratio / projection to cancel `R` | **No** — no edge weight is a *known* multiple of `R`; ratios only relate unknown randoms. |
| `sigma` / parity leakage | **No** — `sigma` ignored at decrypt; it is `H*x xor e` of a random sparse `x`. |
| `pk` leaks `sk` | **No** — `keygen()` samples `canon_tag, prf_k, g, omega_B, lpn_s_bits` independently of `pk`. |
| Statistical bias in `R` / weights | **No** — `R = r1*r2*r3` (hash-to-field), `w` uniform; no observed bias. |
| LPN cryptanalysis of the mask PRF | Reduces to LPN `n=4096, tau=1/8`, **but the LPN samples are never exposed** — no syndrome equations to feed a solver. |

## Why the v1 attack is dead in v2 (two independent proofs)

The published v1 break (Iamknownasfesal, wallet `oct6Y7j...`) needed two things:
1. a **candidate-checkable oracle** `R_com = SHA256(dom||canon_tag||ztag||nonce||1||R)`
   whose only non-public input is `R`; and
2. **single-layer** blocks `T = plaintext_block * R`, so a guessed `x` yields a
   candidate `R = T*x^{-1}` that the oracle confirms.

v2 removes both:

- `R_com` is computed in `synth` but **not serialized** (`write_layer` writes only
  `seed` and `PC`). No hash oracle remains.
- Each block is **wrapped**: `T0 = (v+m)*R0`, `T1 = (-m)*R1` with independent
  masks and a fresh uniform `m`.

**Candidate-verification is now impossible.** For any guessed block value `v`, choose
*any* `m`; then `R0 = T0*(v+m)^{-1}` and `R1 = -T1*m^{-1}` are always consistent.
Every `v` fits the public data equally well => no BIP39/format/dictionary pruning
can work, because there is no public function of a guess to check. (This is the same
reason the pair `(T0,T1)` perfectly hides `v`.)

**The wrapped fusion does not leak like bounty2.** Bounty2's homomorphic-addition
leak required the addends to share mask structure so noise did not cover the sum.
Here the two fused layers have independent masks `R0 != R1` (verified: all 44 layers
in `secret.ct` have distinct seeds; 0 native-source layers), so
`T0 + T1 = (v+m)R0 - m R1` never collapses to a function of `v` alone.

## Full attack enumeration (all closed at `071b0e9`)

1. R_com hash oracle (v1) - removed from wire.
2. Weak/seedable RNG - no; `getrandom()`.
3. `pk` leaks `sk` - no; `keygen()` samples independently.
4. Native-source alt-mask (`ru_r_slots`, only `prf_k`) - 0 present; rejected by `dec_text`.
5. Pedersen `PC` leaks `R^{-1}` - no; blinding `rho` depends on secret `prf_k`, perfectly hiding.
6. `sigma` leaks plaintext - no; `H*x xor e` with random per-edge salt, ignored at decrypt.
7. Edge positions/counts - only depth/length metadata, value-independent.
8. Algebraic mask cancellation (ratios) - no edge weight is a known multiple of `R`.
9. Statistical bias/clustering in `w` - no; `w = R*uniform` is uniform.
10. Wrapped-pair addition leak (bounty2 style) - no; independent masks.
11. Candidate verification via BIP39/format - impossible; every `v` consistent.
12. LPN cryptanalysis - samples never exposed; no syndrome equations available.
13. Cross-cipher mask reuse - no; all seeds distinct (verified).
14. Subgroup structure of `g` (order 337) - multiplicative only; no linear leverage.

## Bottom line

Recovering the plaintext from public files reduces to inverting the LPN-based mask
PRF (recover `sk.lpn_s_bits` / `sk.prf_k`), and the LPN instance is used purely as
an internal PRF whose per-call outputs are never observable. No oracle, bias,
weak-RNG, algebraic linearity, or `pk`->`sk` leak was found. v2 closes the v1 hole
and the residual construction is sound under its LPN/PRF assumptions. The only public
break to date (2026-07-07) is the v1 R_com attack against a different wallet; the v2
target `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ` remains unsolved and, absent
a new implementation flaw in the generation path, is not recoverable ciphertext-only.

## Empirical known-plaintext distinguisher (null result)

`tools/distinguish.cpp` keygens a fresh key, then encrypts N blocks of a *known*
value `v=0` and N of a known nonzero value, round-trips them through the wire
serializer (as the real artifact is), and compares every public statistic:
`u01(T0)`, `u01(T1)`, `u01(T0+T1)`, `u01(T0*T1)`, edge count, and a public
zero-sum test. Result (N=300):

```
v=0    : meanU(T0)=0.4999 meanU(T1)=0.5038 meanU(T0+T1)=0.5204 avgEdges=47.3 zeroSum=0
v=known: meanU(T0)=0.4895 meanU(T1)=0.4754 meanU(T0+T1)=0.4715 avgEdges=47.4 zeroSum=0
```

All statistics coincide within sampling error (~0.017); edge count depends only on
depth; there is no public zero-detection. With full ground truth, no distinguisher
exists -- confirming the value is not leaked by any first/second-order public statistic.

## The final hardening commit

The pinned commit `071b0e9` ("public matrix sampling") is the tip of `main` -- the
challenge runs the latest code, so there is no post-hoc fix to mine. That commit
adds `mixed_weight()` parity mixing to `gen_H`/`sigma_from_H` and a
`test_public_linear_invariants` test. Both harden the **sigma / H-syndrome decoy**
(mixed column parity + full GF(2) rank so sigma's parity is not a fixed linear leak)
-- i.e. recrypt-soundness hardening, not value hiding. It does not touch the
multiplicative mask that protects the plaintext.

## Reproduce

```
# from repo root, with pvac_hfhe_cpp @ 071b0e9 checked out beside source/
g++ -std=c++17 -O2 -march=native \
    -Ipvac_hfhe_cpp/include -Isource tools/probe.cpp -o probe
./probe .     # prints per-layer T_L = target_L * R_L for all 22 ciphers
```
