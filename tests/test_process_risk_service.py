import unittest

from services.risk_service import calculate_event_potentiality, calculate_priority, calculate_process_risk_metrics


class ProcessRiskServiceTest(unittest.TestCase):
    def test_event_potentiality_formula(self):
        self.assertEqual(calculate_event_potentiality(2.5, 2), 3.5)

    def test_process_risk_metrics_from_article_formula(self):
        metrics = calculate_process_risk_metrics(
            probability=2.5,
            vulnerability_level=2,
            impact=3,
            control_effectiveness=0.2,
            cost=2,
            asset_value=8,
        )

        self.assertEqual(metrics["potentiality"], 3.5)
        self.assertEqual(metrics["risk_level"], 10.5)
        self.assertAlmostEqual(metrics["residual_risk"], 8.4)
        self.assertAlmostEqual(metrics["risk_reduction"], 2.1)
        self.assertEqual(metrics["priority"], "HIGH")

    def test_priority_high_for_strong_reduction_high_value_low_cost(self):
        self.assertEqual(calculate_priority(risk_reduction=6, asset_value=9, cost=1), "HIGH")


if __name__ == "__main__":
    unittest.main()
