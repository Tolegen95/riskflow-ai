import unittest

from ai.risk_recommender import analyze_process_risks, recommend_process_risk


class AIAnalysisTest(unittest.TestCase):
    def test_recommends_missing_control_and_high_priority(self):
        recommendation = recommend_process_risk(
            residual_risk=7.4,
            control_effectiveness=0.2,
            control_measure_id=None,
            risk_level="Высокий",
        )

        self.assertIn("назначить контрольную меру", recommendation)
        self.assertIn("усиление контроля", recommendation)
        self.assertIn("приоритетного устранения", recommendation)

    def test_process_analysis_detects_top_risk_and_repeated_factors(self):
        risks = [
            {
                "subprocess_name": "Сбор логов",
                "threat_name": "Вредоносное ПО",
                "vulnerability_name": "Отсутствие мониторинга",
                "control_name": None,
                "control_effectiveness": 0.1,
                "residual_risk": 7.2,
                "risk_level": "Высокий",
            },
            {
                "subprocess_name": "Анализ событий",
                "threat_name": "Вредоносное ПО",
                "vulnerability_name": "Отсутствие мониторинга",
                "control_name": "A.12.4.1 Event logging",
                "control_effectiveness": 0.4,
                "residual_risk": 5.0,
                "risk_level": "Средний",
            },
        ]

        analysis = analyze_process_risks(risks)

        self.assertEqual(analysis["top_risk"]["subprocess_name"], "Сбор логов")
        self.assertEqual(analysis["rating"], "High")
        self.assertEqual(analysis["repeated_threats"][0]["name"], "Вредоносное ПО")
        self.assertEqual(analysis["repeated_vulnerabilities"][0]["name"], "Отсутствие мониторинга")
        self.assertEqual(len(analysis["missing_control_risks"]), 1)


if __name__ == "__main__":
    unittest.main()
