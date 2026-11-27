"""PhiNet R0.2: fixed offline synthetic paired placement study."""
from dataclasses import replace
import json
import random
import statistics

from .phinet_lab import Worker, Task, simulate, digest, canonical

SCHEMA = "PHINET_PLACEMENT_STUDY_R02"
POLICIES = ("first-fit", "compute-rate", "locality")
FAMILIES = ("balanced", "hot-skew", "cold-only", "slow-link", "outage",
            "privacy", "constrained", "fanout", "affinity-trap")
SEEDS = tuple(369 + 97 * i for i in range(27))
METRICS = ("makespan_ticks", "cold_mib", "network_mib", "gpu_job_ticks")


def scenario(family, seed):
    if family not in FAMILIES or type(seed) is not int or seed not in SEEDS:
        raise ValueError("not a frozen scenario")
    r = random.Random(seed)
    workers = (
        Worker("node-a", 22000, 9000, 4000, 1500, 5, 12, 64, ("large",)),
        Worker("node-b", 22000, 7000, 4000, 1500, 3, 7, 64, ("small",)),
        Worker("node-c", 16000, 6000, 4000, 1000, 4, 5, 32, ("small",)),
    )
    if family == "hot-skew":
        workers = tuple(replace(w, hot_models=("large", "small") if w.id == "node-c" else ()) for w in workers)
    elif family == "cold-only":
        workers = tuple(replace(w, hot_models=()) for w in workers)
    elif family == "slow-link":
        workers = tuple(replace(w, link_mib_per_tick=1) for w in workers)
    elif family == "outage":
        index = seed % len(workers)
        workers = tuple(replace(w, online=False) if i == index else w for i, w in enumerate(workers))
    elif family == "constrained":
        workers = tuple(replace(w, gpu_mib=3000, cpu_mib=6500) for w in workers)
    elif family == "affinity-trap":
        # Greedy local decisions can delay a pinned task. This is a
        # constructed counterexample, not an independently sampled workload.
        workers = (
            Worker("node-a", 8000, 0, 1000, 0, 1, 0, 64),
            Worker("node-b", 8000, 0, 1000, 0, 10, 0, 64),
        )
        work = r.randint(10, 90)
        tasks = (
            Task("a-flex", "node-b", "cpu", work, 128, privacy="public", allow_remote=True),
            Task("b-pinned", "node-b", "cpu", 1000 + r.randint(0, 100), 128),
        )
        return workers, tasks
    tasks = []
    for i in range(12):
        tid = f"job-{i:02d}"
        origin = r.choice(workers).id
        gpu = r.random() < .65
        public = r.random() < (.25 if family == "privacy" else .8)
        deps = ()
        if i >= 3:
            if family == "fanout":
                deps = ("job-00",) if i < 11 else tuple(f"job-{j:02d}" for j in range(1, 11))
            elif r.random() < .5:
                deps = tuple(f"job-{j:02d}" for j in sorted(r.sample(range(i), r.randint(1, min(3, i)))))
        model = r.choice(("small", "large")) if gpu else ""
        tasks.append(Task(tid, origin, "gpu" if gpu else "cpu", r.randint(20, 240),
                          r.choice((256, 512, 1024, 4096)),
                          r.choice((512, 1024, 2048, 4096)) if gpu else 0,
                          model, {"small": 2048, "large": 4096}.get(model, 0),
                          r.choice((0, 1, 16, 256)), "public" if public else "private",
                          public and r.random() < .9, deps))
    return workers, tuple(tasks)


def audit_plan(workers, tasks, plan):
    """Independent arithmetic/constraint checks on the emitted records.

    Not a separate scheduler or proof of optimality.
    """
    ws = {w.id: w for w in workers}
    ts = {t.id: t for t in tasks}
    records = plan["records"]
    by_task = {p["task"]: p for p in records}
    if len(records) != len(ts) or set(by_task) != set(ts):
        raise ValueError("incomplete or duplicate coverage")
    if plan["origin"] != "SIMULATED" or plan["authority"] != "NONE":
        raise ValueError("unexpected authority")
    for tid, p in by_task.items():
        t = ts[tid]
        if p["decision"] == "HOLD":
            continue
        if p["decision"] != "SIMULATED_PLACE":
            raise ValueError("unexpected decision")
        w = ws[p["worker"]]
        remote = w.id != t.origin
        if not w.online or (remote and (t.privacy != "public" or not t.allow_remote)):
            raise ValueError("ineligible placement")
        cold = t.cold_mib if t.kind == "gpu" and t.model not in w.hot_models else 0
        rate = w.gpu_rate if t.kind == "gpu" else w.cpu_rate
        net = t.payload_mib if remote else 0
        if not rate or t.ram_mib + w.cpu_reserve > w.cpu_mib or t.vram_mib + cold + w.gpu_reserve > w.gpu_mib:
            raise ValueError("capacity violation")
        link = min(w.link_mib_per_tick, ws[t.origin].link_mib_per_tick)
        ticks = -(-t.work // rate) + -(-cold // 256) + -(-net // link)
        expected = (ticks, cold, net, t.vram_mib + cold, t.ram_mib)
        if tuple(p[k] for k in ("ticks", "cold_mib", "network_mib", "vram_mib", "ram_mib")) != expected:
            raise ValueError("cost mismatch")
        if p["start"] < 0 or p["end"] - p["start"] != ticks:
            raise ValueError("invalid timing")
        for d in t.deps:
            if by_task[d]["decision"] != "SIMULATED_PLACE" or by_task[d]["end"] > p["start"]:
                raise ValueError("dependency violation")
    placed = [p for p in records if p["decision"] == "SIMULATED_PLACE"]
    for w in workers:
        jobs = sorted((p for p in placed if p["worker"] == w.id), key=lambda p: p["start"])
        if any(a["end"] > b["start"] for a, b in zip(jobs, jobs[1:])):
            raise ValueError("worker overlap")
    expected_summary = {
        "placed": len(placed), "held": len(ts) - len(placed),
        "makespan_ticks": max((p["end"] for p in placed), default=0),
        "cold_mib": sum(p["cold_mib"] for p in placed),
        "network_mib": sum(p["network_mib"] for p in placed),
        "gpu_job_ticks": sum(p["ticks"] for p in placed if ts[p["task"]].kind == "gpu"),
    }
    if plan["summary"] != expected_summary:
        raise ValueError("summary mismatch")
    return tuple(sorted(p["task"] for p in placed))


def compare(rows, baseline):
    result = {}
    for metric in METRICS:
        delta = [row["policies"]["locality"]["summary"][metric] -
                 row["policies"][baseline]["summary"][metric] for row in rows]
        result[metric] = {
            "wins": sum(d < 0 for d in delta), "ties": sum(d == 0 for d in delta),
            "losses": sum(d > 0 for d in delta), "median_signed_delta": statistics.median(delta),
            "min_signed_delta": min(delta), "max_signed_delta": max(delta),
        }
    return result


def run_study():
    rows = []
    for family in FAMILIES:
        for i, seed in enumerate(SEEDS):
            workers, tasks = scenario(family, seed)
            plans = {p: simulate(workers, tasks, p) for p in POLICIES}
            coverage = [audit_plan(workers, tasks, plan) for plan in plans.values()]
            if any(c != coverage[0] for c in coverage):
                raise ValueError("unequal task coverage: no performance comparison")
            hashes = {p["input_sha256"] for p in plans.values()}
            if len(hashes) != 1:
                raise ValueError("paired input mismatch")
            rows.append({"family": family, "seed": seed, "split": "development" if i < 9 else "holdout",
                         "input_sha256": hashes.pop(),
                         "policies": {k: {"summary": p["summary"], "receipt_sha256": p["receipt_sha256"]}
                                      for k, p in plans.items()}})
    groups = {}
    for split in ("development", "holdout"):
        for family in (*FAMILIES, "all"):
            group = [r for r in rows if r["split"] == split and (family == "all" or r["family"] == family)]
            groups[f"{split}/{family}"] = {
                "scenarios": len(group),
                "vs_first_fit": compare(group, "first-fit"),
                "vs_compute_rate": compare(group, "compute-rate"),
            }
    body = {"schema": SCHEMA, "origin": "SIMULATED", "authority": "NONE",
            "families": list(FAMILIES), "seeds": list(SEEDS), "policies": list(POLICIES),
            "scenario_count": len(rows), "plan_count": len(rows) * len(POLICIES),
            "rows": rows, "groups": groups}
    return {**body, "report_sha256": digest(body)}


def verify(report):
    # Replays every fixed input, not merely the caller-provided digest.
    return type(report) is dict and canonical(report) == canonical(run_study())


def main():
    print(json.dumps(run_study(), indent=2))


if __name__ == "__main__":
    main()
