import copy
import unittest

from phicloud.phinet_lab import simulate
from phicloud.phinet_study import (
    FAMILIES, SEEDS, POLICIES, audit_plan, run_study, scenario, verify,
)


class PhiNetStudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_study()

    def test_complete_paired_census(self):
        r = self.report
        self.assertEqual((r["scenario_count"], r["plan_count"]), (243, 729))
        self.assertEqual(len({(x["family"], x["seed"]) for x in r["rows"]}), 243)
        self.assertEqual(r["groups"]["holdout/all"]["scenarios"], 162)
        self.assertEqual(r["groups"]["development/all"]["scenarios"], 81)
        for row in r["rows"]:
            self.assertEqual(set(row["policies"]), set(POLICIES))
            counts = {p["summary"]["placed"] for p in row["policies"].values()}
            self.assertEqual(len(counts), 1)
        for group in r["groups"].values():
            for baseline in ("vs_first_fit", "vs_compute_rate"):
                for value in group[baseline].values():
                    self.assertEqual(value["wins"] + value["ties"] + value["losses"], group["scenarios"])

    def test_replay_and_mutation(self):
        self.assertTrue(verify(self.report))
        altered = copy.deepcopy(self.report)
        altered["rows"][0]["policies"]["locality"]["summary"]["cold_mib"] += 1
        self.assertFalse(verify(altered))

    def test_affinity_counterexample(self):
        group = self.report["groups"]["holdout/affinity-trap"]["vs_first_fit"]["makespan_ticks"]
        self.assertEqual(group["losses"], 18)
        self.assertEqual(group["wins"], 0)

    def test_audit_refuses_cost_and_coverage_mutations(self):
        w, t = scenario("affinity-trap", SEEDS[0])
        p = simulate(w, t)
        self.assertEqual(len(audit_plan(w, t, p)), 2)
        bad = copy.deepcopy(p)
        bad["records"][0]["cold_mib"] += 1
        with self.assertRaises(ValueError):
            audit_plan(w, t, bad)
        bad = copy.deepcopy(p)
        bad["records"].pop()
        with self.assertRaises(ValueError):
            audit_plan(w, t, bad)

    def test_frozen_inputs(self):
        self.assertEqual(len(FAMILIES), 9)
        self.assertEqual(len(SEEDS), 27)
        with self.assertRaises(ValueError):
            scenario("unknown", SEEDS[0])
        with self.assertRaises(ValueError):
            scenario("balanced", 1)


if __name__ == "__main__":
    unittest.main()
