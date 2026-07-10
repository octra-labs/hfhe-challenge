import random
# Demonstrate the LPN attack machinery on a SMALL instance where A and y are exposed,
# then show why the challenge exposes neither.
def solve_lpn(k, m, tau, seed=1):
    rnd=random.Random(seed)
    s=[rnd.randint(0,1) for _ in range(k)]
    A=[[rnd.randint(0,1) for _ in range(k)] for _ in range(m)]
    y=[]
    for r in range(m):
        d=sum(a&si for a,si in zip(A[r],s))&1
        e=1 if rnd.random()<tau else 0
        y.append(d^e)
    # Gauss/ISD: pick k rows, hope error-free, solve, verify on rest (majority)
    import itertools
    for attempt in range(20000):
        idx=rnd.sample(range(m),k)
        M=[A[i][:]+[y[i]] for i in idx]
        # gaussian elim over GF(2)
        piv=0; ok=True; rows=M
        for c in range(k):
            pr=next((r for r in range(piv,k) if rows[r][c]),None)
            if pr is None: ok=False; break
            rows[piv],rows[pr]=rows[pr],rows[piv]
            for r in range(k):
                if r!=piv and rows[r][c]:
                    rows[r]=[a^b for a,b in zip(rows[r],rows[piv])]
            piv+=1
        if not ok: continue
        cand=[rows[r][k] for r in range(k)]
        # verify against all samples
        good=0
        for r in range(m):
            d=sum(a&si for a,si in zip(A[r],cand))&1
            good+= (d==y[r])
        if good/m > 0.80:  # matches noise floor
            return cand==s, attempt
    return False, -1

ok,att=solve_lpn(k=20,m=400,tau=1/8)
print(f"TOY LPN k=20, exposed A and y, tau=1/8 -> recovered secret: {ok} (in {att} ISD tries)")
print("This works ONLY because A (the matrix) and y (the syndrome) are both public.")
print()
print("Challenge reality (params k=4096): A is AES-PRG keyed by sk.prf_k (secret),")
print("y is folded into R via secret Toeplitz and never serialized. Exposed rows = 0.")
print("=> the solver above cannot be instantiated: no A, no y. LPN is used as a PRF.")
