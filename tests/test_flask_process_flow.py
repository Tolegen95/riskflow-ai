import os
import tempfile
import unittest

import app as app_module
from ai.risk_recommender import recommend_process_risk


class FlaskProcessFlowTest(unittest.TestCase):
    def setUp(self):
        self.original_database_path = app_module.DATABASE_PATH
        self.temp_dir = tempfile.TemporaryDirectory()
        app_module.DATABASE_PATH = os.path.join(self.temp_dir.name, "test_risk_assessment.db")
        app_module.app.config["TESTING"] = True
        app_module.init_db()
        self._seed_reference_data()
        self.client = app_module.app.test_client()

    def tearDown(self):
        app_module.DATABASE_PATH = self.original_database_path
        self.temp_dir.cleanup()

    def _seed_reference_data(self):
        with app_module.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO threats (name) VALUES (?)", ("Вредоносное ПО",))
            cursor.execute(
                "INSERT INTO vulnerabilities (name, category) VALUES (?, ?)",
                ("Отсутствие мониторинга", "Systems"),
            )
            cursor.execute(
                "INSERT INTO assets (name, life_health, economy, ecology, dependency, social, international, threat_probability) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("SIEM", 8, 8, 4, 9, 7, 6, 2.5),
            )
            conn.commit()

    def _login_admin(self):
        return self.client.post(
            "/login",
            data={"username": "admin", "password": "admin123"},
            follow_redirects=True,
        )

    def _create_process_fixture(self):
        with app_module.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO companies (name, description, industry) VALUES (?, ?, ?)",
                ("Test Company", "Test description", "Security"),
            )
            company_id = cursor.lastrowid
            cursor.execute(
                """
                INSERT INTO processes (company_id, name, description, process_type, owner, input_data, output_data, regulations, resources)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    company_id,
                    "Incident Management",
                    "Incident process",
                    "Security",
                    "SOC",
                    "Logs",
                    "Report",
                    "Policy",
                    "SIEM",
                ),
            )
            process_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO subprocesses (process_id, name, responsible_person, used_systems, order_index) VALUES (?, ?, ?, ?, ?)",
                (process_id, "Collect logs", "Analyst", "SIEM", 1),
            )
            subprocess_id = cursor.lastrowid
            cursor.execute("SELECT id FROM assets WHERE name = ?", ("SIEM",))
            asset_id = cursor.fetchone()[0]
            cursor.execute("SELECT id FROM threats WHERE name = ?", ("Вредоносное ПО",))
            threat_id = cursor.fetchone()[0]
            cursor.execute("SELECT id FROM vulnerabilities WHERE name = ?", ("Отсутствие мониторинга",))
            vulnerability_id = cursor.fetchone()[0]
            cursor.execute("SELECT id FROM control_measures ORDER BY id LIMIT 1")
            control_id = cursor.fetchone()[0]
            initial_risk, residual_risk, risk_level, _ = app_module.calculate_risk(3, 2.8, 0.2)
            cursor.execute(
                """
                INSERT INTO process_risks (
                    process_id, subprocess_id, asset_id, threat_id, vulnerability_id, control_measure_id,
                    risk_description, probability, impact, initial_risk, control_effectiveness,
                    residual_risk, risk_level, ai_recommendation
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    process_id,
                    subprocess_id,
                    asset_id,
                    threat_id,
                    vulnerability_id,
                    control_id,
                    "Delayed incident detection",
                    2.8,
                    3,
                    initial_risk,
                    0.2,
                    residual_risk,
                    risk_level,
                    recommend_process_risk(residual_risk, 0.2, control_id, risk_level),
                ),
            )
            cursor.execute(
                "INSERT INTO process_bpmn (process_id, bpmn_json) VALUES (?, ?)",
                (
                    process_id,
                    '{"nodes":[{"id":"start","type":"start","label":"Start"},{"id":"task1","type":"task","label":"Collect logs"}],"edges":[{"from":"start","to":"task1"}]}',
                ),
            )
            conn.commit()
            return process_id

    def test_admin_login_and_process_pages(self):
        login_response = self._login_admin()
        self.assertEqual(login_response.status_code, 200)

        process_id = self._create_process_fixture()
        for path in [
            "/companies",
            "/processes",
            f"/processes/{process_id}",
            f"/process_report/{process_id}",
            f"/ai_analysis/{process_id}",
            "/process_risks",
        ]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)

        bpmn_response = self.client.get(f"/api/process_bpmn/{process_id}")
        self.assertEqual(bpmn_response.status_code, 200)
        self.assertIn("bpmn", bpmn_response.get_json())

        save_response = self.client.post(
            f"/api/process_bpmn/{process_id}",
            json={
                "nodes": [
                    {"id": "start", "type": "start", "label": "Start"},
                    {"id": "end", "type": "end", "label": "End"},
                ],
                "edges": [{"from": "start", "to": "end"}],
            },
        )
        self.assertEqual(save_response.status_code, 200)
        self.assertTrue(save_response.get_json()["success"])

    def test_create_company_and_process_via_routes(self):
        self._login_admin()

        company_response = self.client.post(
            "/companies/add",
            data={"name": "Route Company", "description": "Created by test", "industry": "Finance"},
            follow_redirects=True,
        )
        self.assertEqual(company_response.status_code, 200)
        self.assertIn("Route Company".encode(), company_response.data)

        with app_module.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM companies WHERE name = ?", ("Route Company",))
            company_id = cursor.fetchone()[0]

        process_response = self.client.post(
            "/processes/add",
            data={
                "company_id": company_id,
                "name": "Route Process",
                "description": "Created by test",
                "process_type": "Compliance",
                "owner": "Owner",
                "input_data": "Input",
                "output_data": "Output",
                "regulations": "Rules",
                "resources": "People",
            },
            follow_redirects=True,
        )
        self.assertEqual(process_response.status_code, 200)
        self.assertIn("Route Process".encode(), process_response.data)


if __name__ == "__main__":
    unittest.main()
