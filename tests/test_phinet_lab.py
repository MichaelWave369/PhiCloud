import copy
from dataclasses import replace
import unittest

from phicloud.phinet_lab import Worker, Task, fixture, simulate, verify


class PhiNetLabTests(unittest.TestCase):
    def setUp(self):
        self.workers, self.tasks = fixture()

    def run_lab(self, workers=None, tasks=None, policy="locality"):
        return simulate(self.workers if workers is None else workers,
                        self.tasks if tasks is None else tasks, policy)

    def record(self, receipt, tid):
        return next(r for r in receipt["records"] if r["task"] == tid)

    def test_repeat_and_order_independent(self):
        a = self.run_lab()
        self.assertEqual(a, self.run_lab(self.workers[::-1], self.tasks[::-1]))
        self.assertTrue(verify(self.workers, self.tasks, a))
        self.assertEqual(a["authority"], "NONE")

    def test_mutated_receipt(self):
        r = copy.deepcopy(self.run_lab())
        r["summary"]["placed"] += 1
        self.assertFalse(verify(self.workers, self.tasks, r))

    def test_privacy_and_hold_propagation(self):
        r = self.run_lab()
        self.assertEqual(self.record(r, "d-private")["worker"], "node-a")
        self.assertEqual(self.record(r, "e-oversize")["reason"], "NO_ELIGIBLE_WORKER")
        self.assertEqual(self.record(r, "f-dependent")["reason"], "DEPENDENCY_HELD")
        self.assertEqual(r["summary"]["held"], 2)

    def test_dependencies_and_no_overlap(self):
        r = self.run_lab()
        joined = self.record(r, "c-synthesis")
        for d in ("a-extract", "b-review"):
            self.assertGreaterEqual(joined["start"], self.record(r, d)["end"])
        for w in self.workers:
            jobs = sorted((x for x in r["records"] if x.get("worker") == w.id),
                          key=lambda x: x["start"])
            for a, b in zip(jobs, jobs[1:]):
                self.assertLessEqual(a["end"], b["start"])
            for j in jobs:
                self.assertLessEqual(j["vram_mib"] + w.gpu_reserve, w.gpu_mib)
                self.assertLessEqual(j["ram_mib"] + w.cpu_reserve, w.cpu_mib)

    def test_cpu_only_and_remote_consent(self):
        w = replace(self.workers[0], online=False)
        t = Task("cpu-job", "node-a", "cpu", 10, 20, privacy="public")
        self.assertEqual(self.run_lab((w, self.workers[1]), (t,))["summary"]["held"], 1)
        allowed = replace(t, allow_remote=True)
        r = self.run_lab((w, self.workers[1]), (allowed,))
        self.assertEqual(r["summary"]["placed"], 1)
        self.assertEqual(r["summary"]["gpu_job_ticks"], 0)
        self.assertEqual(self.run_lab((w, self.workers[1]), (replace(allowed, privacy="private"),))["summary"]["held"], 1)

    def test_hot_vs_cold_baseline(self):
        t = self.tasks[1]
        a = self.run_lab(tasks=(t,), policy="first-fit")
        b = self.run_lab(tasks=(t,), policy="locality")
        self.assertEqual(a["summary"]["cold_mib"], 4096)
        self.assertEqual(b["summary"]["cold_mib"], 0)
        self.assertEqual(self.record(b, t.id)["worker"], "node-b")
        self.assertEqual(a["summary"]["placed"], b["summary"]["placed"])

    def test_gpu_absent(self):
        w = replace(self.workers[0], gpu_rate=0)
        t = replace(self.tasks[1], privacy="private")
        self.assertEqual(self.record(self.run_lab((w, self.workers[1]), (t,)), t.id)["denied"]["node-a"], "NO_GPU")

    def test_invalid_fixture(self):
        t = self.tasks[0]
        for bad in (replace(t, deps=("missing",)), replace(t, deps=(t.id,)),
                    replace(t, work=True), replace(t, ram_mib=-1),
                    replace(t, model="unexpected"), replace(t, allow_remote=1)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.run_lab(tasks=(bad,))
        with self.assertRaises(ValueError):
            self.run_lab(tasks=(t, t))
        with self.assertRaises(ValueError):
            self.run_lab(workers=(replace(self.workers[0], gpu_reserve=10000), self.workers[1]))
        with self.assertRaises(ValueError):
            self.run_lab(policy="unknown")


if __name__ == "__main__":
    unittest.main()
