import math
# LPN instance behind the mask PRF (from params.json)
k = 4096          # lpn_n: secret dimension
t = 16384         # lpn_t: rows per prf_R_core call
tau = 1/8         # lpn_tau_num/den

def H2(p): return -p*math.log2(p)-(1-p)*math.log2(1-p) if 0<p<1 else 0.0

print(f"LPN: dim k={k}, samples/call t={t}, noise tau={tau}")
print(f"  binary entropy H2(tau) = {H2(tau):.4f} bits/sample")

# 1) Gaussian-elimination / ISD-style: need k clean rows out of t; each row clean w.p. (1-tau)
#    expected tries to draw k rows all clean ~ (1-tau)^-k
gauss = -k*math.log2(1-tau)
print(f"  [Gauss/ISD, sample-hungry] ~2^{gauss:.0f} (draw {k} noise-free eqns; only have t={t}<<needed)")

# 2) BKW (blockwise): a=log2 blocks, complexity ~ 2^{k/log2(k)} ballpark (Lyubashevsky/Levieil-Fouque regime)
bkw = k/math.log2(k)
print(f"  [BKW ballpark] ~2^{bkw:.0f}")

# 3) Pooled-Gauss / covering-codes rough optimum (Esser-Kuebler-May style): exponent ~ c*k
#    with tau=1/8, published estimates land well above 2^128 for k>=512.
print(f"  [Best-known asymptotic exponents all exceed 2^128 for k={k}, tau={tau}]")

# Data availability: how many LPN equations does the PUBLIC artifact expose?
print()
print("Observable LPN syndrome bits in the public artifact:")
print("  ybits are consumed inside prf_R_core -> toeplitz -> hash_to_fp -> R (never serialized)")
print("  R itself is never public; only T = v*R is public (v unknown).")
print("  => exposed LPN equations = 0.  No solver can even be instantiated.")
