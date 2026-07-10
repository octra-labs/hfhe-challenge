# The LPN Angle — Attempt and Result

The mask that hides every plaintext is `R = prf_R(sk, seed) = r1*r2*r3`, and each
`ri = hash_to_fp_nonzero(Toeplitz127( y ))` where `y` is an **LPN syndrome**:

```
y_r = <A_r, s> XOR e_r ,   r = 0..t-1
```

with secret `s = sk.lpn_s_bits` (dimension `k = lpn_n = 4096`), `t = lpn_t = 16384`
rows per call, and Bernoulli noise `tau = lpn_tau_num/den = 1/8`
(`crypto/lpn.hpp: lpn_make_ybits`).

Recovering `s` would let an attacker recompute every `R` and decrypt. So: can we
mount an LPN attack?

## Step 1 — Is there an observable LPN instance? No.

An LPN solver needs the pairs `(A_r, y_r)`. In this construction **both are secret**:

- `A_r` (the row generator) is an AES-CTR PRG whose key is
  `derive_aes_key(pk, sk, seed, dom)` = `SHA256(sk.prf_k || canon_tag || H_digest ||
  seed || dom)` — keyed by the secret `sk.prf_k` (`lpn.hpp:318`). The matrix is not public.
- `y_r` is consumed inside `prf_R_core` -> `Toeplitz127` (Toeplitz key also derived
  from `sk.prf_k`) -> `hash_to_fp_nonzero` -> `R`. The syndrome is never serialized.
- `R` itself is never public either; only `T = v*R` appears, with `v` unknown.

**Exposed LPN equations in the public artifact: 0.** The LPN instance is used purely
as a PRF (both matrix and syndrome hidden). No solver — ISD, BKW, Gauss, covering
codes, lattice — can even be *instantiated*, because there is no `(A, y)` to feed it.

`tools/lpn_demo.py` shows the ISD machinery recovering a `k=20` secret in ~40 tries
*when `A` and `y` are exposed*, and states plainly why it cannot start here.

## Step 2 — Even if the syndrome were exposed, is it feasible? No.

For `k = 4096, tau = 1/8` (`tools/lpn_estimate.py`):

| Method | Rough cost |
| --- | --- |
| Gauss / ISD (needs `k` noise-free rows; only `t=16384` available) | ~2^789 |
| BKW ballpark (`k / log2 k`) | ~2^341 |
| Best-known asymptotic exponents (Esser-Kuebler-May etc.) | all > 2^128 for `k>=512, tau=1/8` |

The parameters were chosen (per Octra's docs, citing MIPT results on random-hypergraph
threshold/colorability) to sit far above any practical break.

## Step 3 — Does knowing a plaintext block help? No.

`secret.ct` has 21 block-ciphers, so the message length is one of only 15 values
(301..315 bytes). But the length cipher, like every block, is **wrapped** with its own
independent masks: `T0 = (len+m)R0`, `T1 = (-m)R1`. Knowing `len` still leaves
`m, R0, R1` free, and — crucially — every other block uses **independent** masks
(all 44 seeds distinct, verified). A known plaintext in one block yields nothing about
any other. There is no cross-instance leverage from a single artifact.

## Conclusion

The LPN attack is blocked twice over: there is no observable instance (matrix and
syndrome both secret, `R` never revealed), and the underlying `k=4096, tau=1/8`
instance would be infeasible even if it were observable. The mask PRF stands exactly
as the design intends: `R` is LPN-hard to recover, and nothing in the public artifact
gives a foothold to attack it.
