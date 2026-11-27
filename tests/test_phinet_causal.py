import copy
import unittest

from phicloud.phinet_lab import simulate
from phicloud.phinet_study import SEEDS as OLD_SEEDS, run_study as historical_study
from phicloud.phinet_causal import R02_REPORT, FAMILIES, SEEDS, run_study, scenario, verify


class PhiNetCausalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_study()

    def test_historical_receipt_unchanged(self):
        self.assertEqual(historical_study()["report_sha256"], R02_REPORT)

    def test_new_cohort_and_coverage(self):
        self.assertFalse(set(OLD_SEEDS) & set(SEEDS))
        self.assertEqual((self.report["scenario_count"], self.report["plan_count"]), (243, 972))
        self.assertEqual(len({(r["family"], r["seed"]) for r in self.report["rows"]}), 243)
        for row in self.report["rows"]:
            self.assertEqual(len({p["summary"]["placed"] for p in row["policies"].values()}), 1)
        for group in self.report["groups"].values():
            for key in ("vs_first_fit", "vs_compute_rate", "vs_locality"):
                for metric in group[key].values():
                    self.assertEqual(metric["wins"] + metric["ties"] + metric["losses"], group["scenarios"])

    def test_constructed_positive_and_negative_controls(self):
        groups = self.report["groups"]
        self.assertEqual(groups["affinity-control"]["vs_locality"]["makespan_ticks"]["wins"], 27)
        self.assertEqual(groups["scarcity-counterexample"]["vs_locality"]["makespan_ticks"]["losses"], 27)

    def test_ready_frontier_order_and_determinism(self):
        workers, tasks = scenario("affinity-control", SEEDS[0])
        plan = simulate(workers, tasks, "scarcity")
        self.assertEqual(plan["records"][0]["task"], "b-pinned")
        self.assertEqual(plan, simulate(workers[::-1], tasks[::-1], "scarcity"))

    def test_replay_and_tampering(self):
        self.assertTrue(verify(self.report))
        altered = copy.deepcopy(self.report)
        altered["rows"][0]["seed"] += 1
        self.assertFalse(verify(altered))

    def test_closed_scenario_set(self):
        self.assertEqual(len(FAMILIES), 9)
        with self.assertRaises(ValueError):
            scenario("mixed", 369)


if __name__ == "__main__":
    unittest.main()
