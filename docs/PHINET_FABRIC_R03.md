# PhiNet R0.3 · Causal scarcity-first placement

**SIMULATED / authority NONE.** R0.2 PR #23 actual workflow
[45947513856](https://github.com/MichaelWave369/PhiCloud/actions/runs/45947513856)
reported 243 scenarios / 729 plans. On 162 holdout-labelled scenarios
locality versus first-fit had 21/91/50 makespan wins/ties/losses and
29/122/11 cold-weight wins/ties/losses. The 18 affinity controls all
lost on makespan. Report SHA-256 is frozen in the new study; exact
historical regeneration is mandatory.

## Candidate

Order pending tasks by total eligible-worker count (ascending), longest
downstream DAG edge depth (descending), then lexical ID. Only causally
ready tasks are placed; all R0.1 constraints remain. Choose the idle
worker using the same full-cost locality ranking. No lookahead to
future arrivals, no waiting for a better busy worker, no preemption or
physical reservation. This is scarcity-priority, not a live lease.

## New cohort

Nine families, 27 new seeds (90369 + 113*i), four policies, 243 scenarios
and 972 plans. Seven authored stochastic families plus two constructed
controls. Affinity-control should favor scarcity; scarcity-counterexample
should expose its tendency to send flexible long work to slow idle
workers when waiting would be better. These controls are deliberately
constructed, not sampled evidence. No claims of independent test data
or optimality; the cohort is fixed but not a blinded preregistration.

    python -m phicloud.phinet_causal > phinet-r03-report.json
    python -m unittest discover -s tests -p 'test_phinet*.py' -v

The full paired report includes signed metrics, every seed, input and
receipt digest, exact task identity coverage and the existing arithmetic
audit. The old R0.2 report must reproduce byte-equivalent canonical
content. No task effects are executed. Static workloads and resident
sets only; no deadlines, shared-link contention, dependency output
transfers, inherited information-flow labels or dynamic failure. The
existing metadata privacy checks do not prove safe cross-task data
flow. No actual GPU load, energy, speedup or remote security claims.
The default and historical R0.1/R0.2 policies are unchanged.

Next: review both positive and negative results, then evaluate a
wait-aware finish-time policy on a separately defined cohort. Read-only
PhiStream/PhiServe evidence adapters remain a distinct gated track.
