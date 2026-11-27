# PhiNet R0.1 · Sovereign Computational Fabric Laboratory

**SIMULATED / authority NONE / offline only.** PhiNet is already named in
PhiCloud's service architecture. This standalone standard-library module
explores task placement without changing the registry, HTTP services,
credentials, inference backends or any other repository.

## Reproduce

    python -m phicloud.phinet_lab
    python -m unittest discover -s tests -p test_phinet_lab.py -v

The fixed two-worker fixture compares deterministic first-fit and locality
placement using identical jobs, capacity and permissions. It includes a
CPU extraction, a GPU review with a warm model on the second worker,
a dependent synthesis, a private CPU task, an oversized GPU task and
a dependent refusal. All values are invented. The fixture is not a
benchmark of a 5070, 3060, or any physical computer.

## Contract

* Bounded immutable synthetic Worker and Task records, unique identifiers,
  exact integer resource units and a validated acyclic dependency graph.
* Each worker represents one exclusive physical node, with one active
  job at a time. CPU/RAM and GPU budgets are independent; protected
  reserves cannot be assigned. GPU budget means free space AFTER fixed
  resident weights, so only workspace and additional cold weights are
  charged. Cold weights are not retained between jobs.
* Private tasks stay at the origin; public cross-node tasks require
  explicit remote consent. Offline workers and insufficient capacity
  are refused. A held dependency propagates HOLD.
* First-fit uses lexical eligible idle worker order. Locality ranks
  eligible idle workers by estimated duration, then cold and network
  bytes, then worker ID. Both use the same task-ID ordering, deterministic
  completion events and nonpreemptive assignments. No future lookahead.
* Duration uses invented integer work rates, fixed local staging rate
  256 MiB/tick and a synthetic link rate. No output payload or shared-link
  contention modeled. No actual CPU/GPU utilization is observed.
* SHA-256 receipts bind the canonical input and complete plan. Replay
  checks consistency, not identity, authority or actual job completion.

## Reviewed upstream boundaries (design references, not imported code)

- [PocketMesh E0](https://github.com/MichaelWave369/NBGPocketMesh/blob/main/docs/E0_PROTOCOL.md):
  strict eligibility, privacy, memory and latency budgets.
- [Altermath causal belt](https://github.com/MichaelWave369/Altermath/blob/main/docs/CAUSAL_POCKET_MACHINE_R1.md):
  explicit dependencies and finite delegation.
- [Agentora local leases](https://github.com/MichaelWave369/Agentora/blob/main/docs/FLEET_R04_LOCAL_LEASES.md):
  expiry/fencing concepts; no distributed lease implied.
- [PhiServe R14](https://github.com/MichaelWave369/PhiServe/blob/main/docs/QUEUED_ADMISSION_R14.md):
  existing bounded local inference queue remains independent.
- [PhiServe R15](https://github.com/MichaelWave369/PhiServe/blob/main/docs/HARDWARE_ADVISOR_R15.md):
  review-only observed capacity evidence; no live routing.
- [PhiStream PocketRotor E2](https://github.com/MichaelWave369/PhiStream/blob/main/docs/POCKETROTOR_E2.md):
  finite expert residency, charge all speculative transfers.
- [PhiMemory9](https://github.com/MichaelWave369/PhiMemory9):
  retrieval/continuity, not an inference KV cache.

## Limitations and next gate

The simulator does not execute a job, spawn a process, open a listener,
discover devices, read real models or private data, enforce actual VRAM,
measure energy, reduce real GPU load, change permissions or verify model
quality. No failover, persistent lease, retry, remote transport, shared
bandwidth, actual KV residency or hierarchical allocation is implemented.
The toy duration objective does not establish optimization superiority.
Synthetic outcomes may be biased toward the chosen fixture.

Next: freeze multiple workload families and held-out seeds; compare
first-fit, least-load and locality under equal budgets, including shifted
residency, worker outage and link-contention controls. Separately propose
read-only adapters to the existing PhiStream/PhiServe field receipts.
Do not enable real job placement before independent contract and security
review. Existing local/offline services must continue to work independently.
