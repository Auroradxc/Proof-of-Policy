# Caption drafts (IEEE style)

Each caption follows the same order: **what is shown → measurement conditions
(n, units, source, `proof_mode`/vkey) → what must not be inferred**. They are
written to be pasted into `\caption{}`; the LaTeX blocks are the exact drafts.
All data figures are single measurements unless stated otherwise; no caption
claims a confidence interval that was not measured.

---

## Fig. 1 — `fig01_architecture.pdf`

```latex
\caption{Proof-of-Policy architecture. A policy package is compiled to a
\texttt{ConstraintSpec} (the compiled NFA, the only object crossing the layer
boundary), evaluated by the zkVM guest on the response $T$, and turned into a
DSSE/Ed25519-signed certificate. Public values bind the response
($b=H(\mathrm{dom}\Vert n\Vert T)$), commit to the policy
(\texttt{policy\_commit}$=H(s\Vert\pi)$), and carry the verdict and the
disclosure level. Blue: public values; orange: witness or secret; green:
verified or anchored. The dashed boundary is the untrusted operator; no TEE is
assumed, and the signing and tool-gateway keys remain trust roots. The
verifier supplies the challenge nonce $n$. The end-user delivery path $T''$ is
not covered by the certificate's binding to the verifier's copy $T'$
(Proposition~1). This is a design diagram, not a measured hiding claim:
\texttt{core} reports \texttt{hiding=none}, and \texttt{gr\-oth16} hiding is
wrapper-level and not post-quantum.}
\label{fig:architecture}
```

**Do not infer:** that the operator is trusted, that the certificate covers
delivery to the end user, or that `core` hides its witness.

---

## Fig. 2 — `fig02_bhv_leakage.pdf`

```latex
\caption{(a) The binding--hiding--verifiability (BHV) classification. Below the
entropy threshold $k_X<\log q+\log(1/\varepsilon)$, at most two of
guess-tight binding, exact-recovery hiding, and publicly recomputable
verification (PV-2) coexist. (b) Leakage profile of Theorem~1 for the response
$T$, the request nonce $n$, and the policy $\pi$, across public values
($L_{\mathrm{pub}}$), proof artefact ($L_{\mathrm{proof}}$), and side
information ($L_{\mathrm{side}}$). Each cell is split into \texttt{core} and
\texttt{gr\-oth16} (g16); \emph{closed}, \emph{bounded}, and \emph{open} describe
only the named channel. \texttt{core} leaves the trace and opened values in
$L_{\mathrm{proof}}$; \texttt{gr\-oth16} closes that channel at wrapper level
but is not post-quantum. The salted policy commitment closes the hash channel
and loses PV-2. No proof tier closes $L_{\mathrm{side}}$: re-execution and
dictionary attacks remain, and a zero canary probe is not a zero-knowledge
proof. The matrix is conceptual, not a measured recovery rate.}
\label{fig:bhv}
```

**Do not infer:** that `groth16` makes the response unrecoverable, that a
salted policy is fully private, or that any column other than the named one is
closed.

---

## Fig. 4 — `fig04_cycles_vs_length.pdf`

```latex
\caption{(a) zkVM execution cycles versus response length for five fixed rule
sets (1, 2, 3, 4, and 6 rules; 0--3 keyword and 0--2 regular-expression rules).
Points are the 30 Pike-mode measurements of the 40-point matrix
(\texttt{bench/results/cycles.json}); lines are per-rule-set ordinary least
squares, with $R^2=1.0000$ throughout. (b) Fitted per-character slope. One NFA
regular expression raises the slope from 73.9--105.3 to 4{,}049--5{,}404
cycles/character, a factor of 58 between the endpoint rule sets. The corpus is
a 372-character demo artefact tiled to longer lengths, so this is the curve of
scanning cost, not a real 100{,}000-character document; every point was
confirmed to match no rule. Execution only, no proof. The unit-price model
$cycles\approx a|T|\cdot rules+b$ is refuted ($R^2=0.917$, negative keyword
price) and is not plotted; per-rule-set slopes are the citable quantities.}
\label{fig:cycles}
```

**Do not infer:** that the 100k point is a real document, that a unit price is
additive across rule kinds, or that these are proving costs.

---

## Fig. 5 — `fig05_matcher_ablation.pdf`

```latex
\caption{(a) zkVM execution cycles for pattern \texttt{a+b} on input
\texttt{a}$^n$ with no match, comparing naive re-anchoring with the Pike VM
(\texttt{bench/results/ablation.json}; $n=100,200,400$). Dotted grey lines are
$\Theta(n^2)$ and $\Theta(n)$ references anchored at $n=100$; the naive/Pike
ratios are $19.2\times$, $42.5\times$, and $90.1\times$. (b) Proving path on a
24-core / 14.6\,GiB host (\texttt{dos\_proof.json}; \texttt{core}, pre-NFA-fix
binary \texttt{b81e6d07\ldots}). Pike at $n=100$ proved in 122.2\,s at
11.70\,GiB; naive at $n=25$ proved in 153.2\,s at 12.14\,GiB; naive at $n=50$
was OOM/SIGKILLed after 226.5\,s at 13.77\,GiB measured peak. The cross is an
observed kill, not a smoothed point. No $n\ge100$ naive or $n=400$ proving
point was measured, so no proving curve is drawn. Execution and proving counts
come from separate driver builds and differ by about one part in $10^5$.}
\label{fig:ablation}
```

**Do not infer:** that the proving cost is quadratic beyond the measured
points, that the execution and proving counters are identical builds, or that
the OOM point has a usable peak-RSS value beyond the observed kill.

---

## Fig. 6 — `fig06_proof_feasibility.pdf`

```latex
\caption{Real SP1 proofs on the 16-core / 92{,}160\,MiB cloud cgroup
(post-NFA-fix binary \texttt{7f99fdb1\ldots}, policy vkey
\texttt{0x003eb14d\ldots}; one proof per process, serially).
(a) Proving wall time versus peak RSS for the 18-point $3\times3\times2$ matrix,
the six-rule length sweep, and the EU AI Act pack. Blue: \texttt{core};
orange: \texttt{gr\-oth16}; green: \texttt{core} with six rules; stars: EU AI
Act. Crosses mark observed SIGKILL/OOM events, placed at the cgroup limit
because their peak RSS was not measured; they are not connected.
(b) \texttt{core} feasibility grid over length and rule count: the set is not a
rectangle ($2000\times3$ succeeds at 33.9\,GiB while $10000\times3$ is killed).
(c) Six-rule peak RSS versus length: 4500 passed at 62.7\,GiB with 20{,}480\,B
of cgroup headroom after reclaiming 5.27\,GB of page cache; 5000 was killed
after 157.7\,s. $GiB=peak\_rss\_mb/1024$; the source counter is MiB. Table~I prints the
same counter divided by 1000 under the label GB, so its values are 2.4\%
larger. Re-runs show $\pm10\%$ wall-clock and $\pm1\%$ memory jitter; these are
single measurements, so no error bars are drawn. The boundary is a function of
this host, the default prover options, and the rule \emph{kind}, not of the
proof system alone; 4750 was not measured and six-rule \texttt{gr\-oth16} was
not attempted.}
\label{fig:proofs}
```

**Do not infer:** that OOM points have a measured peak, that the feasible set
is rectangular, that the boundary transfers to another machine or to different
SP1 prover knobs, or that six-rule `groth16` was measured.

---

## Fig. 6b — `fig06b_proof_main.pdf` (main-text candidate)

```latex
\caption{Real SP1 proofs on the 16-core / 92{,}160\,MiB cgroup (post-NFA-fix,
policy vkey \texttt{0x003eb14d\ldots}). Blue: \texttt{core}; orange:
\texttt{gr\-oth16}; green: \texttt{core} with six rules; stars: EU AI Act.
Crosses mark observed SIGKILL/OOM events at the cgroup limit; their peak RSS
was not measured, and they are not interpolated. The core floor is
$\approx$10.2\,GiB; \texttt{gr\-oth16} adds about 19\,GiB and is largely
insensitive to length. The per-point numeric table is in the supplementary
material. Single runs; $\pm10\%$ time and $\pm1\%$ memory jitter.}
\label{fig:proofs-main}
```

**Do not infer:** that the crosses have measured peak RSS; that the same
boundary holds on another host or with different prover knobs.

---

## Fig. 7 — `fig07_k_est.pdf`

```latex
\caption{(a) Teacher-forced estimate $k^{\mathrm{est}}$ of the guessing entropy
of the response for Qwen2.5-7B-Instruct and Mistral-7B-Instruct-v0.3, on 50
XSTest prompts with 20 samples per prompt at temperature 0.7 (chat template).
The dashed line is the 40-bit threshold
$\log_2 q+\log_2(1/\varepsilon)$ with $q=2^{20}$ and
$\varepsilon=2^{-20}$. Because $k^{\mathrm{est}}$ is an \emph{upper} bound on
the true $k$ (the estimator maximizes over sampled sequences), points to the
left of 40 bit refute the 40-bit condition---16/50 Qwen and 11/50 Mistral
groups do so---while points to the right do not certify it.
(b) Greedy decoding at temperature 0: $k=0$ in all 50/50 groups for both
models, so one re-execution recovers $T$. The two temperatures are shown
separately because $k=0$ cannot share a log axis with positive estimates.
Source: \texttt{k\_logprobs.json} and
\texttt{e6\_mistral/k\_logprobs.json}.}
\label{fig:kest}
```

**Do not infer:** that $k^{\mathrm{est}}$ is a lower bound, that the groups
right of 40 bit satisfy the threshold, or that the N=20 exact-string
estimator (which hits $\log_2 20$) measures the same quantity.

---

## Fig. 8 — `fig08_policy_disclosure.pdf`

```latex
\caption{Policy-inference attack over three disclosure levels. (a,b) A1:
20 synthetic policy variants, 11 templates per variant, 40 training and 15
test responses per variant, multinomial naive Bayes (\texttt{policy\_infer.json}).
L2 here is the count-only projection. (c,d) E2: 300 candidate policies, 220
real chat responses, 19{,}800 test pairs, v1 certificate payload
(\texttt{policy\_corpus\_infer.json}); L2 carries deterministic evidence
commitments and L2* is the count-only projection used in A1. Top-1/top-3
recover the generating variant; normalized MI and audit utility are on a
0--1 scale. Chance top-1 is 0.050 (A1) and 0.0033 (E2). The two corpora are
never averaged: the synthetic curve estimates leakage from the projection,
while the real-response panel shows that coarse format/length/budget rules
dominate the 0.677 evidence coverage. \texttt{policy\_hash} is excluded from
the features (a candidate-corpus lookup would give top-1 $=1.0$). The v2
circuit-level L2 has not been re-measured.}
\label{fig:policy-disclosure}
```

**Do not infer:** that A1 and E2 are the same attack, that L2 is random on the
v1 payload, that L2 and L2* are the same projection, or that the v2 circuit
values were measured.

---

## Fig. 9 — `fig09_issuance_detection.pdf`

```latex
\caption{(a) Exact probability of detecting at least one withheld violation
when auditing delivered artifacts, $1-\binom{N-m}{s}/\binom{N}{s}$, for
$N=2000$ deliveries, $s=\mathrm{round}(pN)$, $m$ withheld violations, and
$p\in\{0.01,\ldots,0.20\}$. Markers are exact values; 500 Monte Carlo trials
per cell (seed 20261101) agree within sampling noise. (b) At $p=0.05$,
$s=100$, $m=100$, the delivered-artifact frame detects 0.9948, while the
log-entry frame detects 0.0000 because withheld deliveries have no log entry:
the sample frame, not luck, is the issue. This quantifies detection under
independent violations, not prevention; append-before-delivery is an external
premise, and a common root cause makes $m$ not an independent event count.}
\label{fig:issuance}
```

**Do not infer:** that the cryptography forces issuance, that 0.0000 is a
sampling accident, or that detection equals prevention.

---

## Caption checklist

- State the measured quantity first, then the unit and $n$/configuration, then
  the source file and the `proof_mode`/vkey if relevant.
- Name the exact tier: `core` is not zero-knowledge; `groth16` hiding is
  wrapper-level and not post-quantum.
- For OOM, write “observed kill” and where the marker is placed; never call it
  an interpolated point.
- For $k^{\mathrm{est}}$, write “upper bound” and state the one-sided reading.
- For policy inference, keep A1 and E2 separate and name L2 vs L2*.
- For issuance, write “detection, not prevention”.
- Do not add error bars, CIs, or “typical” values that are not in the result
  files.
