# C2 circuit-level disclosure results (cloud run)

Source: `docs/experiments/circuit-disclosure.md` §6.1.

- Build: AutoDL, rustc/cargo 1.99.1, succinct 1.94.0-dev.
- `pop-script` sha256: `374ee241a72a5e5d55b69248f5812255d7a19dc32e8abede6b347ce0c684e13c`
- policy guest vkey: `0x000cfdfc7325f13f5887e434baa89860aae6675f0f30ec2b480dfe98b62c0b2a`
- Proofs: `core` only. `proof_L{0,1,2}.json` are the decoded public values;
  `verify_L{0,1,2}.json` are the verifier outputs (`verified=true` in each).

Do not mix these with the local smoke-test build: the local rustc 1.98.1 build
has a different ELF/vkey. The local proof is not an experimental result.
