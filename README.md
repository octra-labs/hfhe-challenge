# hfhe challenge

This wallet holds 500,000 OCT:

`oct6Y7jxx92V5nuUykotRqHj6xPz1JEiT3ZRswJ4Awvi9Zn`

Funding transaction:

`4d597770acef403a9bc3bb555e962c00b749247139605737b71f97d09c5b0370`

The wallet mnemonic was encrypted directly using the pinned `pvac_hfhe_cpp` implementation.

public files:

- `seed.ct`: the encrypted wallet mnemonic
- `pk.bin`: the public HFHE key material
- `params.json`: encryption parameters
- `manifest.json`: challenge metadata
- `SHA256SUMS`: hashes of all published artifacts
- `source/`: the exact artifact generation and serialization source

There is no passphrase, PBKDF2, AES-GCM, sealed storage envelope, or additional encryption layer protecting the mnemonic.

No recrypt, Rku, NatKey, eval key, or reset material is published.

The winning condition is simple: recover the mnemonic encrypted in `seed.ct` and use it to submit a valid transaction from the funded wallet before the challenge is withdrawn.

The secret key and plaintext mnemonic are not published.
