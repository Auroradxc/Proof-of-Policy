# Caption drafts — VA figure set (IEEE style)

Each caption follows the same order: **what is shown → configuration/units/
source → what must not be inferred**. These are drafts for the supplement; the
LaTeX blocks are the exact text. They assume the main paper's `pdflatex` /
IEEEtran preamble, so math mode is used only in captions, never in the figure
PDFs (the figure PDFs embed TrueType only).

---

## VA1 — `va01_deployment_trust.pdf`

```latex
\caption{Three-party deployment and trust boundaries of PoP (design, not
measured). The policy authority holds $\pi$ and salt $s$ and publishes
$h_\pi=H(s\Vert\pi)$; the operator is untrusted and runs the agent, compiler,
zkVM guest, optional tool gateway and signer without a TEE; the verifier
supplies a fresh $n$, receives $T'$ and the certificate, recomputes
$b=H(\mathrm{dom}\Vert n\Vert T')$, and checks the delegated companion and
ledger inclusion. Blue: public/verifier-visible; orange: witness or secret;
green: signed or anchored; dashed: external assumption or open gap. Trust
anchors are the signing key, the gateway key and the policy registry/P-PP, not
the operator machine. The certificate binds the verifier's copy $T'$, not the
end-user delivery $T''$ (Proposition~1). \texttt{core} leaves the witness open;
\texttt{gr\-oth16} hiding is wrapper-only and not post-quantum;
$L_{\mathrm{side}}$ (re-execution) is open at every tier. No TEE is assumed.
This is a design diagram, not an implementation trace or a measured hiding
claim.}
\label{fig:va-deployment}
```

**Do not infer:** that the operator is trusted; that a TEE exists; that the
certificate covers $T''$; that `core` is zero-knowledge; that `groth16` is
post-quantum; that the trust roots are cryptographic rather than key-custody
and registry assumptions.

---

## VA2 — `va02_certificate_lifecycle.pdf`

```latex
\caption{Certificate issuance and verification as a design contract (not a
measured latency trace). Steps 1--10 order the obligations: policy issuance;
\texttt{ConstraintSpec} compilation (the same bytes cross the layer boundary);
a fresh 256-bit challenge $n$; streamed generation with early stop; policy
check $J(\pi,T)$; proof tier (\texttt{core}/\texttt{gr\-oth16}/\texttt{unproven});
DSSE/Ed25519 signing and append-before-delivery; delivery of $T'$ and the
certificate; conjunctive verification (signature, nonce freshness, proof tier,
recomputed $b=H(\mathrm{dom}\Vert n\Vert T')$, $h_\pi$ in P-PP, delegated
companion, ledger inclusion); and accept/reject. Dashed boxes F1--F8 are
fail-closed exits: any one rejects and no proof tier is silently downgraded.
Boundaries: \texttt{core} is not ZK; \texttt{gr\-oth16} hiding is wrapper-only;
\texttt{unproven} is host-check only; append-before-delivery is external; the
end-user binding $T''$ remains open. Step numbers are obligations, not
timestamps.}
\label{fig:va-lifecycle}
```

**Do not infer:** a deployment latency or ordering in wall-clock time; that a
policy violation is a system failure (the certificate can be valid with
`passed=false`); that `unproven` is a proof; that `T''` is covered; that the
ledger is implemented with consistency proofs or gossip.

---

## VA3 — `va03_comparison_matrix.pdf`

```latex
\caption{Categorical cross-system comparison. (a) The seven dimensions of
Table~S6: 49 cells, 46 populated and 3 unavailable (Zaguk size, PCO latency,
PCO size). Cell tint encodes evidence status---$[m]$ measured here, $[c]$
cited and not reproduced, em dash unavailable and not estimated---not quality
or rank; the thin bar encodes only the named privacy category
(closed/bounded/open/n.a.). (b) Three dimensions requested by the brief that
are not in Table~S6: proof obligation, issuance/audit, implementation status.
Only explicitly documented cells are filled; em dash means not reported, not
inferred. PoP latency is cloud \texttt{core} 39.8--100.3\,s and
\texttt{gr\-oth16} 279.3--343.8\,s (16-core / 92{,}160\,MiB cgroup,
post-NFA-fix) with local verification 89.84\,ms; the lower core bound is
39.83\,s in \texttt{scale-cloud.json}, whereas Table~S6 rounds it to 40.5\,s.
\texttt{gr\-oth16} proof size is 1{,}874--1{,}875\,B across the nine successful
points (Table~S6 prints 1{,}874\,B). Measured arms: $n=500$ repetitions for the
Merkle timing medians, $n=300$ for the TEE simulation, and single proof runs for
PoP with $\pm10\%$ wall-clock and $\pm1\%$ peak-RSS jitter. No continuous score,
ranking or interpolation is implied.}
\label{fig:va-comparison}
```

**Do not infer:** a single ranking across systems that prove different
obligations; that cited cells were reproduced here; that `—` is zero; that the
TEE arm measured hardware attestation; that PoP is faster or slower than a
system with a different obligation and host.

---

## VA4 — `va04_claim_evidence.pdf`

```latex
\caption{Claim--evidence matrix. Rows are seven claims; columns are E1
(guessing-entropy samples, $N=50$ and cross-model), E6 (teacher-forced
$k^{\mathrm{est}}$ upper bound), E2 (300-candidate L2 inference), E3 (real
DeepSeek agent end-to-end), X1 (cloud \texttt{core}/\texttt{gr\-oth16} matrix),
C2 (circuit-level L0/L1/L2), and CC (composition negative controls). Each cell
is \emph{supports}, \emph{refutes}, or \emph{unknown}, with numeric evidence
read from the named JSON and asserted at build time; the source file is printed
in the cell. \emph{unknown} means the experiment does not address the claim,
not a negative result. C-k is refuted by E6 (16/50 Qwen and 11/50 Mistral
groups below 40 bit) while E1 is N-capped and cannot certify it; C-L2 is
supported by E2 (L2 top-1 $0.382$ vs L2$^{*}$ $0.014$ constructive, $0.112$ vs
$0.017$ real); C-OOM and C-cost are supported by X1 (16/18 pass, 2 OOM;
\texttt{core} 39.8--100.3\,s, \texttt{gr\-oth16} 279.3--343.8\,s; single runs
with $\pm10\%$ time and $\pm1\%$ memory jitter); C-e2e is
supported by E3 with \texttt{proof\_mode=unproven} (host-check only); C-deleg
is supported by CC cell~d (true but unsatisfied, fail closed); C-strong is
refuted by CC cell~c (weak form only, proof debt E-1). Verdicts are an author
mapping, not a statistical test.}
\label{fig:va-claims}
```

**Do not infer:** that `unknown` is evidence against a claim; that E3 proves
model compliance; that E1 certifies $k\ge40$ bit; that C2 implemented the
delegated companion; that E2/C2 numbers transfer across vkeys, corpora or
proof modes; that C-strong is satisfied.

---

## Caption checklist

- [ ] The figure is labelled a design/contract when it is not a measured trace.
- [ ] `core` vs `groth16` hiding is stated correctly; no tier closes `L_side`.
- [ ] The end-user `T''` gap is stated; no TEE is claimed.
- [ ] `[m]`/`[c]`/`—` are defined in the caption, not only in the legend.
- [ ] `—` is described as unavailable, not zero and not interpolated.
- [ ] `k_est` is an upper bound; E1 is N-capped.
- [ ] E3 is host-check only (`proof_mode=unproven`).
- [ ] C2 did not implement `delegated`; CC cell c is the weak form (E-1).
- [ ] The caption says what cannot be inferred from the figure.
