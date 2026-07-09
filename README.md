# HFHE Challenge v2
This is the second version of the bounty challenge, the first having been cancelled due to configuration issues.

The entire task boils down to attempting to recover or crack the plaintext encryption path using the provided binary artifact -`secret.ct`. This file contains a private key and metadata associated with the address `octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ`. 

That is all the information provided (a web client can be used to access the wallet).

The rest of the bounty package remains unchanged:
- manifest.json
- params.json
- pk.bin
- pvac_commit.txt
- secret.ct
- source/hfhe_bounty_artifact.cpp
- source/pvac_artifact_serialize.hpp

Please also note that the ciphertext was generated using a slightly updated version of pvac-hfhe (latest commit: 071b0e9); it is recommended to use this specific version for testing attacks.