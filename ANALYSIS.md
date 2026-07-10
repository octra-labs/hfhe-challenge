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

## Bottom line

Recovering the plaintext from public files reduces to inverting the LPN-based mask
PRF (recover `sk.lpn_s_bits` / `sk.prf_k`), and the LPN instance is used purely as
an internal PRF whose per-call outputs are never observable. No oracle, bias,
weak-RNG, algebraic linearity, or `pk`->`sk` leak was found. v2 closes the v1 hole
and the residual construction is sound under its LPN/PRF assumptions.
