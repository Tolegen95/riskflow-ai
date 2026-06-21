import unittest

import app as app_module


class RiskCalculationTest(unittest.TestCase):
    def test_low_risk_includes_zero(self):
        risk_score, residual_risk, risk_level, interpretation = app_module.calculate_risk(2, 2, 1)

        self.assertEqual(risk_score, 4)
        self.assertEqual(residual_risk, 0)
        self.assertEqual(risk_level, "Низкий")
        self.assertEqual(interpretation, "Допустимый, контрольный")

    def test_medium_risk(self):
        _, residual_risk, risk_level, _ = app_module.calculate_risk(2.5, 2, 0)

        self.assertEqual(residual_risk, 5)
        self.assertEqual(risk_level, "Средний")

    def test_high_risk(self):
        _, residual_risk, risk_level, _ = app_module.calculate_risk(3, 3, 0)

        self.assertEqual(residual_risk, 9)
        self.assertEqual(risk_level, "Высокий")


if __name__ == "__main__":
    unittest.main()
