# HFHE challenge

> status: paused

This challenge is no longer active.

The original challenge used the directly exposed proof-of-concept text-encryption path. It has been paused while the challenge construction is revised.

The wallet binding, transaction details, and active bounty condition have been removed from the current version of this repository.

The published cryptographic artifacts and generation source remain available for reproducibility and analysis.

## public artifacts

- `seed.ct`: encrypted challenge plaintext
- `pk.bin`: public HFHE key material
- `params.json`: encryption parameters
- `manifest.json`: challenge metadata
- `pvac_commit.txt`: exact `pvac_hfhe_cpp` commit used
- `SHA256SUMS`: hashes of the published files
- `source/`: artifact generation and serialization source

## status

Paused. A revised challenge will be published separately.
