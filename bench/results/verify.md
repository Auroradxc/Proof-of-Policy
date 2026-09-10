# Verification cost (`pop-script --verify`)

| proof | cold CLI (s) | vkey setup (s) | pure verify (ms) |
|---|---:|---:|---:|
| bench/work/proof.bin | 22.799 | 1.616 | 89.84 |

> `cold CLI` includes constructing the SP1 prover client (heavy); `pure verify` is
> vkey-setup once + N verifications — what a verifier-only binary would pay.
> A verifier-only path (no prover construction) is future work.
