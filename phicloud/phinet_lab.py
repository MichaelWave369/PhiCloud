"""PhiNet R0.1: offline synthetic placement, never a dispatcher."""
from dataclasses import dataclass, asdict
import hashlib
import json
import re

SCHEMA = "PHINET_PLACEMENT_R01"
MAX_ITEMS = 64
POLICIES = ("first-fit", "locality", "compute-rate", "scarcity")
ID = re.compile(r"[a-z][a-z0-9-]{0,47}", re.ASCII)


def ident(value):
    if type(value) is not str or ID.fullmatch(value) is None:
        raise ValueError("invalid identifier")


def bounded(value, minimum=0):
    if type(value) is not int or not minimum <= value <= 10**9:
        raise ValueError("invalid bounded integer")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


@dataclass(frozen=True)
class Worker:
    id: str
    cpu_mib: int
    gpu_mib: int
    cpu_reserve: int
    gpu_reserve: int
    cpu_rate: int
    gpu_rate: int
    link_mib_per_tick: int
    hot_models: tuple = ()
    online: bool = True


@dataclass(frozen=True)
class Task:
    id: str
    origin: str
    kind: str
    work: int
    ram_mib: int
    vram_mib: int = 0
    model: str = ""
    cold_mib: int = 0
    payload_mib: int = 0
    privacy: str = "private"
    allow_remote: bool = False
    deps: tuple = ()


def validate(workers, tasks):
    if not 1 <= len(workers) <= MAX_ITEMS or not 1 <= len(tasks) <= MAX_ITEMS:
        raise ValueError("fixture size out of bounds")
    for w in workers:
        if type(w) is not Worker:
            raise ValueError("worker schema")
        ident(w.id)
        for x in (w.cpu_mib, w.gpu_mib, w.cpu_reserve, w.gpu_reserve, w.gpu_rate):
            bounded(x)
        for x in (w.cpu_rate, w.link_mib_per_tick):
            bounded(x, 1)
        if w.cpu_reserve > w.cpu_mib or w.gpu_reserve > w.gpu_mib:
            raise ValueError("reserve exceeds capacity")
        if type(w.online) is not bool or type(w.hot_models) is not tuple or len(w.hot_models) > 16:
            raise ValueError("worker flags")
        for m in w.hot_models:
            ident(m)
        if len(set(w.hot_models)) != len(w.hot_models):
            raise ValueError("duplicate hot model")
    ws = {w.id: w for w in workers}
    if len(ws) != len(workers):
        raise ValueError("duplicate worker")
    for t in tasks:
        if type(t) is not Task:
            raise ValueError("task schema")
        ident(t.id)
        ident(t.origin)
        if t.origin not in ws or t.kind not in ("cpu", "gpu") or t.privacy not in ("private", "public"):
            raise ValueError("task contract")
        if type(t.allow_remote) is not bool or type(t.deps) is not tuple or len(t.deps) > MAX_ITEMS:
            raise ValueError("task flags")
        for x in (t.ram_mib, t.vram_mib, t.cold_mib, t.payload_mib):
            bounded(x)
        bounded(t.work, 1)
        if t.kind == "gpu":
            ident(t.model)
            if t.vram_mib == 0 or t.cold_mib == 0:
                raise ValueError("GPU job requires workspace and cold weight estimate")
        elif t.vram_mib or t.cold_mib or t.model != "":
            raise ValueError("CPU task cannot reserve GPU weights")
        for d in t.deps:
            ident(d)
        if len(set(t.deps)) != len(t.deps):
            raise ValueError("duplicate dependency")
    ts = {t.id: t for t in tasks}
    if len(ts) != len(tasks):
        raise ValueError("duplicate task")
    done = set()
    while len(done) < len(ts):
        ready = {t.id for t in tasks if t.id not in done and set(t.deps) <= done}
        if not ready:
            raise ValueError("missing dependency or cycle")
        done |= ready
    return ws, ts


def ceildiv(a, b):
    return (a + b - 1) // b


def estimate(w, t, ws):
    if not w.online:
        return None, "OFFLINE"
    remote = w.id != t.origin
    if remote and (t.privacy != "public" or not t.allow_remote):
        return None, "REMOTE_DENIED"
    if t.ram_mib > w.cpu_mib - w.cpu_reserve:
        return None, "RAM_BUDGET"
    if t.kind == "gpu" and not w.gpu_rate:
        return None, "NO_GPU"
    cold = t.cold_mib if t.kind == "gpu" and t.model not in w.hot_models else 0
    # Free budget is after fixed resident weights; hot model bytes are not charged twice.
    if t.vram_mib + cold > w.gpu_mib - w.gpu_reserve:
        return None, "VRAM_BUDGET"
    # Abstract fixture units only. Local weight staging has its own fixed synthetic rate.
    net = t.payload_mib if remote else 0
    duration = ceildiv(t.work, w.gpu_rate if t.kind == "gpu" else w.cpu_rate)
    duration += ceildiv(cold, 256) + ceildiv(net, min(w.link_mib_per_tick, ws[t.origin].link_mib_per_tick))
    return {"ticks": duration, "cold_mib": cold, "network_mib": net,
            "vram_mib": t.vram_mib + cold, "ram_mib": t.ram_mib}, None


def simulate(workers, tasks, policy="locality"):
    """All inputs are synthetic, metadata only. One active job per physical node."""
    if policy not in POLICIES:
        raise ValueError("unknown policy")
    ws, ts = validate(workers, tasks)
    pending = set(ts)
    if policy == "scarcity":
        eligible_counts = {tid: sum(estimate(w, t, ws)[0] is not None for w in workers)
                           for tid, t in ts.items()}
        # Longest downstream path in edges, calculated without recursion.
        depth = {}
        while len(depth) < len(ts):
            for tid in sorted(ts):
                children = [child.id for child in tasks if tid in child.deps]
                if tid not in depth and all(c in depth for c in children):
                    depth[tid] = max((1 + depth[c] for c in children), default=0)
    completed, held, active, records = set(), set(), {}, []
    clock = 0
    while pending or active:
        for wid in sorted(active):
            finish, tid = active[wid]
            if finish == clock:
                completed.add(tid)
        active = {wid: pair for wid, pair in active.items() if pair[0] > clock}
        progress = True
        while progress:
            progress = False
            order = sorted(pending, key=lambda tid: (eligible_counts[tid], -depth[tid], tid)) if policy == "scarcity" else sorted(pending)
            for tid in order:
                t = ts[tid]
                if set(t.deps) & held:
                    records.append({"task": tid, "decision": "HOLD", "reason": "DEPENDENCY_HELD"})
                    pending.remove(tid)
                    held.add(tid)
                    progress = True
                    continue
                if not set(t.deps) <= completed:
                    continue
                candidates, denied = [], {}
                for wid in sorted(ws):
                    plan, reason = estimate(ws[wid], t, ws)
                    if plan is None:
                        denied[wid] = reason
                    else:
                        candidates.append((wid, plan))
                if not candidates:
                    records.append({"task": tid, "decision": "HOLD", "reason": "NO_ELIGIBLE_WORKER",
                                    "denied": denied})
                    pending.remove(tid)
                    held.add(tid)
                    progress = True
                    continue
                free = [(wid, plan) for wid, plan in candidates if wid not in active]
                if not free:
                    continue
                if policy in ("locality", "scarcity"):
                    free.sort(key=lambda p: (p[1]["ticks"], p[1]["cold_mib"], p[1]["network_mib"], p[0]))
                elif policy == "compute-rate":
                    free.sort(key=lambda p: (-(ws[p[0]].gpu_rate if t.kind == "gpu" else ws[p[0]].cpu_rate), p[0]))
                wid, plan = free[0]
                end = clock + plan["ticks"]
                records.append({"task": tid, "decision": "SIMULATED_PLACE", "worker": wid,
                                "start": clock, "end": end, **plan})
                active[wid] = (end, tid)
                pending.remove(tid)
                progress = True
        if active:
            clock = min(finish for finish, _ in active.values())
        elif pending:
            raise RuntimeError("invalid scheduler state")
    placed = [r for r in records if r["decision"] == "SIMULATED_PLACE"]
    inputs = {"workers": [asdict(ws[k]) for k in sorted(ws)],
              "tasks": [asdict(ts[k]) for k in sorted(ts)]}
    body = {"schema": SCHEMA, "origin": "SIMULATED", "authority": "NONE", "policy": policy,
            "input_sha256": digest(inputs), "records": records,
            "summary": {"placed": len(placed), "held": len(held), "makespan_ticks": clock,
                        "cold_mib": sum(r["cold_mib"] for r in placed),
                        "network_mib": sum(r["network_mib"] for r in placed),
                        "gpu_job_ticks": sum(r["ticks"] for r in placed if ts[r["task"]].kind == "gpu")}}
    return {**body, "receipt_sha256": digest(body)}


def verify(workers, tasks, receipt):
    if type(receipt) is not dict or receipt.get("policy") not in POLICIES:
        return False
    return canonical(receipt) == canonical(simulate(workers, tasks, receipt["policy"]))


def fixture():
    # Synthetic free budgets AFTER fixed resident weights, not actual machine readings.
    workers = (
        Worker("node-a", 22000, 9000, 4000, 1500, 5, 12, 64, ("large",)),
        Worker("node-b", 22000, 7000, 4000, 1500, 3, 7, 64, ("small",)),
    )
    tasks = (
        Task("a-extract", "node-a", "cpu", 50, 512, privacy="public", allow_remote=True),
        Task("b-review", "node-a", "gpu", 120, 512, 1024, "small", 4096, 1,
             "public", True),
        Task("c-synthesis", "node-a", "gpu", 180, 1024, 2048, "large", 8192,
             deps=("a-extract", "b-review")),
        Task("d-private", "node-a", "cpu", 15, 128),
        Task("e-oversize", "node-a", "gpu", 100, 512, 10000, "large", 8192),
        Task("f-dependent", "node-a", "cpu", 20, 128, deps=("e-oversize",)),
    )
    return workers, tasks


def main():
    workers, tasks = fixture()
    print(json.dumps({p: simulate(workers, tasks, p) for p in ("first-fit", "locality")}, indent=2))


if __name__ == "__main__":
    main()
