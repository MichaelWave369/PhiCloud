"""R0.3 fresh synthetic cohort; scarcity-first ready frontier, no real reservations."""
from dataclasses import replace
import json
import random
import statistics

from .phinet_lab import Worker, Task, simulate, digest, canonical
from .phinet_study import audit_plan, run_study as historical_study

SCHEMA = "PHINET_CAUSAL_STUDY_R03"
FAMILIES = ("mixed", "pinned", "asymmetric", "slow-link", "cold", "outage",
            "chain", "affinity-control", "scarcity-counterexample")
SEEDS = tuple(90369 + 113 * i for i in range(27))
POLICIES = ("first-fit", "compute-rate", "locality", "scarcity")
METRICS = ("makespan_ticks", "cold_mib", "network_mib", "gpu_job_ticks")
R02_REPORT = "12f3dcac27f772a2c6e72ded27a1629c1941efdcd090676fdd82319227fa615c"


def scenario(family, seed):
    if family not in FAMILIES or type(seed) is not int or seed not in SEEDS:
        raise ValueError("unregistered scenario")
    r = random.Random(seed)
    if family in ("affinity-control", "scarcity-counterexample"):
        workers = (Worker("node-a", 8192, 0, 1024, 0, 1, 0, 64),
                   Worker("node-b", 8192, 0, 1024, 0, 10, 0, 64))
        if family == "affinity-control":
            flexible, pinned = r.randint(10, 90), r.randint(1000, 1100)
        else:
            # A flexible long job should wait for the fast node, but
            # scarcity-first immediately commits it to the slow idle node.
            flexible, pinned = r.randint(300, 500), r.randint(10, 30)
        return workers, (
            Task("a-flex", "node-b", "cpu", flexible, 128, privacy="public", allow_remote=True),
            Task("b-pinned", "node-b", "cpu", pinned, 128),
        )
    workers = (
        Worker("node-a", 19000, 10000, 3000, 2000, 6, 14, 48, ("large",)),
        Worker("node-b", 15000, 6800, 3000, 1400, 4, 8, 24, ("small",)),
        Worker("node-c", 11000, 4400, 2000, 1000, 3, 5, 12, ("small",)),
    )
    if family == "asymmetric":
        workers = (workers[0], replace(workers[1], cpu_rate=1, gpu_rate=2),
                   replace(workers[2], cpu_rate=9, gpu_rate=0, hot_models=(), gpu_mib=0, gpu_reserve=0))
    elif family == "slow-link":
        workers = tuple(replace(w, link_mib_per_tick=1) for w in workers)
    elif family == "cold":
        workers = tuple(replace(w, hot_models=()) for w in workers)
    elif family == "outage":
        off = seed % 3
        workers = tuple(replace(w, online=False) if i == off else w for i, w in enumerate(workers))
    tasks = []
    for i in range(15):
        origin = r.choice(workers).id
        gpu = r.randrange(3) != 0
        public = r.random() < (.25 if family == "pinned" else .75)
        deps = ()
        if i and family == "chain":
            deps = (f"job-{i-1:02d}",) if i % 3 else ()
        elif i > 2 and r.random() < .6:
            deps = tuple(f"job-{d:02d}" for d in sorted(r.sample(range(i), r.randint(1, min(3, i)))))
        model = r.choice(("small", "large")) if gpu else ""
        tasks.append(Task(f"job-{i:02d}", origin, "gpu" if gpu else "cpu",
                          r.randint(15, 300), r.choice((256, 768, 1536, 6144)),
                          r.choice((512, 1024, 3072)) if gpu else 0, model,
                          {"small": 2304, "large": 4608}.get(model, 0),
                          r.choice((0, 4, 64, 512)), "public" if public else "private",
                          public and r.random() < .9, deps))
    return workers, tuple(tasks)


def compare(rows, baseline):
    result = {}
    for metric in METRICS:
        values = [r["policies"]["scarcity"]["summary"][metric] -
                  r["policies"][baseline]["summary"][metric] for r in rows]
        result[metric] = dict(wins=sum(x < 0 for x in values), ties=sum(x == 0 for x in values),
                              losses=sum(x > 0 for x in values), median_signed_delta=statistics.median(values),
                              min_signed_delta=min(values), max_signed_delta=max(values))
    return result


def run_study():
    rows = []
    for family in FAMILIES:
        for seed in SEEDS:
            workers, tasks = scenario(family, seed)
            plans = {p: simulate(workers, tasks, p) for p in POLICIES}
            coverage = [audit_plan(workers, tasks, plan) for plan in plans.values()]
            if any(x != coverage[0] for x in coverage):
                raise ValueError("unequal task coverage")
            hashes = {p["input_sha256"] for p in plans.values()}
            if len(hashes) != 1:
                raise ValueError("unpaired inputs")
            rows.append(dict(family=family, seed=seed, input_sha256=hashes.pop(),
                             policies={k: dict(summary=v["summary"], receipt_sha256=v["receipt_sha256"])
                                       for k, v in plans.items()}))
    groups = {}
    for family in (*FAMILIES, "all"):
        group = [r for r in rows if family == "all" or r["family"] == family]
        groups[family] = dict(scenarios=len(group),
                              **{f"vs_{p.replace('-', '_')}": compare(group, p) for p in POLICIES[:-1]})
    body = dict(schema=SCHEMA, origin="SIMULATED", authority="NONE",
                historical_r02_sha256=R02_REPORT, families=list(FAMILIES), seeds=list(SEEDS),
                scenario_count=len(rows), plan_count=len(rows)*len(POLICIES), rows=rows, groups=groups)
    return {**body, "report_sha256": digest(body)}


def verify(report):
    return type(report) is dict and canonical(report) == canonical(run_study())


def main():
    if historical_study()["report_sha256"] != R02_REPORT:
        raise RuntimeError("historical R0.2 report drift")
    print(json.dumps(run_study(), indent=2))


if __name__ == "__main__":
    main()
