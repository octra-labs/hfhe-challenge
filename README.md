# Bounty Challenge v2

This is the second version of the bounty challenge, the first having been cancelled due to configuration issues.

Your task is to recover the plaintext from the provided artifact—`secret.ct`—which contains metadata (the address for a successful bounty submission and a secret key). The reward remains unchanged: 500k OCT.

The rest of the bounty package remains the same:

- `manifest.json`
- `params.json`
- `pk.bin`
- `pvac_commit.txt`
- `secret.ct`
- `source/hfhe_bounty_artifact.cpp`
- `source/pvac_artifact_serialize.hpp`

Please also note that the ciphertext was generated using a slightly updated version of pvac-hfhe (latest commit: 071b0e9); it is recommended to use this specific version for testing attacks.