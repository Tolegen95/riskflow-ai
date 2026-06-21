"""
Полное тестирование RiskFlow AI по ролям и функционалу.

Покрытие:
- 5 ролей: admin, risk_manager, process_owner, expert, auditor
- Аутентификация и авторизация
- Все основные маршруты
- Workflow рисков (5 переходов)
- BPMN API
- Создание данных через маршруты
- Разграничение видимости данных
"""

import os
import tempfile
import unittest

from werkzeug.security import generate_password_hash

import app as app_module
from ai.risk_recommender import recommend_process_risk


# ---------------------------------------------------------------------------
# Базовый класс с seed-данными
# ---------------------------------------------------------------------------

class BaseRoleTest(unittest.TestCase):
    """Инициализирует БД, создаёт пользователей всех ролей и общие фикстуры."""

    def setUp(self):
        self.original_db = app_module.DATABASE_PATH
        self.temp_dir = tempfile.TemporaryDirectory()
        app_module.DATABASE_PATH = os.path.join(self.temp_dir.name, "test.db")
        app_module.app.config["TESTING"] = True
        app_module.app.config["WTF_CSRF_ENABLED"] = False
        app_module.init_db()
        self._seed_all()
        self.client = app_module.app.test_client()

    def tearDown(self):
        app_module.DATABASE_PATH = self.original_db
        self.temp_dir.cleanup()

    # ------------------------------------------------------------------
    # Seed helpers
    # ------------------------------------------------------------------

    # Пароли по роли: admin использует стандартный пароль из init_db
    ROLE_PASSWORDS = {
        "admin":         "admin123",
        "risk_manager":  "rm_pass",
        "process_owner": "po_pass",
        "expert":        "ex_pass",
        "auditor":       "aud_pass",
    }

    def _seed_all(self):
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            # admin уже создан в init_db с паролем admin123 — остальные роли добавляем
            for username, role in [
                ("risk_manager",  "risk_manager"),
                ("process_owner", "process_owner"),
                ("expert",        "expert"),
                ("auditor",       "auditor"),
            ]:
                c.execute(
                    "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?,?,?)",
                    (username, generate_password_hash(self.ROLE_PASSWORDS[username]), role),
                )
            # Справочники
            c.execute("INSERT INTO threats (name) VALUES (?)", ("Фишинг",))
            c.execute(
                "INSERT INTO vulnerabilities (name, category) VALUES (?,?)",
                ("Нет MFA", "Access"),
            )
            c.execute(
                "INSERT INTO assets (name,life_health,economy,ecology,dependency,social,international,threat_probability) VALUES (?,?,?,?,?,?,?,?)",
                ("Email-сервер", 5, 8, 3, 9, 6, 5, 2.5),
            )
            # Компания и процесс
            c.execute(
                "INSERT INTO companies (name, description, industry) VALUES (?,?,?)",
                ("CSIRT", "Служба реагирования", "Security"),
            )
            company_id = c.lastrowid
            # Получить owner_user_id для process_owner
            c.execute("SELECT id FROM users WHERE username='process_owner'")
            po_user_id = c.fetchone()[0]
            c.execute(
                """INSERT INTO processes
                   (company_id, name, description, process_type, owner, owner_user_id,
                    input_data, output_data, regulations, resources)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (company_id, "Incident Management", "Процесс ИМ", "Security",
                 "SOC Lead", po_user_id, "Алерты", "Отчёт", "ISO 27035", "SIEM"),
            )
            self.process_id = c.lastrowid
            c.execute(
                "INSERT INTO subprocesses (process_id, name, responsible_person, used_systems, order_index) VALUES (?,?,?,?,?)",
                (self.process_id, "Triage", "Analyst", "SIEM", 1),
            )
            self.subprocess_id = c.lastrowid
            # Риск
            c.execute("SELECT id FROM assets WHERE name='Email-сервер'")
            asset_id = c.fetchone()[0]
            c.execute("SELECT id FROM threats WHERE name='Фишинг'")
            threat_id = c.fetchone()[0]
            c.execute("SELECT id FROM vulnerabilities WHERE name='Нет MFA'")
            vuln_id = c.fetchone()[0]
            c.execute("SELECT id FROM control_measures ORDER BY id LIMIT 1")
            ctrl_row = c.fetchone()
            ctrl_id = ctrl_row[0] if ctrl_row else None
            ir, rr, rl, _ = app_module.calculate_risk(3, 2.5, 0.1)
            c.execute(
                """INSERT INTO process_risks
                   (process_id, subprocess_id, asset_id, threat_id, vulnerability_id,
                    control_measure_id, risk_description, probability, impact,
                    initial_risk, control_effectiveness, residual_risk, risk_level,
                    status, ai_recommendation)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (self.process_id, self.subprocess_id, asset_id, threat_id, vuln_id,
                 ctrl_id,
                 "Нет процедуры triage", 3, 2.5, ir, 0.1, rr, rl,
                 "Draft",
                 recommend_process_risk(rr, 0.1, ctrl_id, rl)),
            )
            self.risk_id = c.lastrowid
            # BPMN
            c.execute(
                "INSERT INTO process_bpmn (process_id, bpmn_json) VALUES (?,?)",
                (self.process_id,
                 '{"nodes":[{"id":"s","type":"start","label":"Start"},{"id":"t1","type":"task","label":"Triage"}],"edges":[{"from":"s","to":"t1"}]}'),
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Login helpers
    # ------------------------------------------------------------------

    def _login(self, role: str):
        password = self.ROLE_PASSWORDS.get(role, role + "_pass")
        return self.client.post(
            "/login",
            data={"username": role, "password": password},
            follow_redirects=True,
        )

    def _logout(self):
        self.client.get("/logout", follow_redirects=True)

    def _get_ok(self, path: str, msg: str = ""):
        r = self.client.get(path)
        self.assertIn(r.status_code, (200, 302), f"GET {path} → {r.status_code} {msg}")
        return r

    def _get_200(self, path: str, msg: str = ""):
        r = self.client.get(path)
        self.assertEqual(r.status_code, 200, f"GET {path} → {r.status_code} {msg}")
        return r

    def _assert_redirected(self, path: str, msg: str = ""):
        r = self.client.get(path)
        self.assertIn(r.status_code, (302, 403), f"Ожидали редирект для {path}: {msg}")

    def _post(self, path: str, data: dict, expect: int = 200):
        r = self.client.post(path, data=data, follow_redirects=True)
        self.assertEqual(r.status_code, expect, f"POST {path} → {r.status_code}")
        return r

    def _post_json(self, path: str, json_data: dict):
        return self.client.post(path, json=json_data)

    def _workflow(self, action: str, comment: str = ""):
        return self.client.post(
            f"/process_risks/{self.risk_id}/workflow",
            data={"action": action, "comment": comment},
            follow_redirects=True,
        )

    def _set_risk_status(self, status: str):
        with app_module.get_db_connection() as conn:
            conn.execute(
                "UPDATE process_risks SET status=? WHERE id=?",
                (status, self.risk_id),
            )
            conn.commit()


# ===========================================================================
# 1. АУТЕНТИФИКАЦИЯ
# ===========================================================================

class TestAuthentication(BaseRoleTest):

    def test_login_page_accessible_without_auth(self):
        r = self.client.get("/login")
        self.assertEqual(r.status_code, 200)

    def test_redirect_to_login_when_unauthenticated(self):
        for path in ["/", "/dashboard", "/processes", "/process_risks"]:
            r = self.client.get(path, follow_redirects=False)
            self.assertEqual(r.status_code, 302, f"Ожидали редирект для {path}")
            self.assertIn("/login", r.location, f"{path} должен редиректить на /login")

    def test_all_roles_can_login_and_logout(self):
        for role in ["admin", "risk_manager", "process_owner", "expert", "auditor"]:
            r = self._login(role)
            self.assertEqual(r.status_code, 200, f"Логин {role} не удался")
            r = self.client.get("/logout", follow_redirects=False)
            self.assertEqual(r.status_code, 302)

    def test_wrong_password_rejected(self):
        r = self.client.post(
            "/login",
            data={"username": "admin", "password": "wrong"},
            follow_redirects=True,
        )
        self.assertEqual(r.status_code, 200)
        self.assertIn("Неверное".encode(), r.data)

    def test_nonexistent_user_rejected(self):
        r = self.client.post(
            "/login",
            data={"username": "nobody", "password": "pass"},
            follow_redirects=True,
        )
        self.assertIn("Неверное".encode(), r.data)


# ===========================================================================
# 2. РОЛЬ: ADMIN — полный доступ
# ===========================================================================

class TestAdminRole(BaseRoleTest):

    def setUp(self):
        super().setUp()
        self._login("admin")

    def test_admin_sees_all_main_pages(self):
        pages = [
            "/dashboard",
            "/methodology",
            "/user_guide",
            "/audit_log",
            "/data_quality",
            "/companies",
            "/processes",
            f"/processes/{self.process_id}",
            f"/process_report/{self.process_id}",
            f"/ai_analysis/{self.process_id}",
            "/process_risks",
            "/risk_treatments",
            "/risk_workflow",
            "/responsibility_matrix",
            "/compliance",
            "/operational_analytics",
            "/my_tasks",
            "/users",
            "/experts",
        ]
        for path in pages:
            self._get_200(path, f"admin должен видеть {path}")

    def test_admin_bpmn_api_get(self):
        r = self.client.get(f"/api/process_bpmn/{self.process_id}")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("bpmn", data)

    def test_admin_bpmn_api_save(self):
        r = self._post_json(
            f"/api/process_bpmn/{self.process_id}",
            {"nodes": [{"id": "s", "type": "start", "label": "S"},
                       {"id": "e", "type": "end", "label": "E"}],
             "edges": [{"from": "s", "to": "e"}]},
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["success"])

    def test_admin_can_create_user(self):
        r = self._post("/users/add", {
            "username": "new_user",
            "password": "secure_pass123",
            "role": "auditor",
        })
        self.assertEqual(r.status_code, 200)
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT username FROM users WHERE username='new_user'")
            self.assertIsNotNone(c.fetchone())

    def test_admin_can_create_company_and_process(self):
        r = self._post("/companies/add", {
            "name": "New Corp", "description": "Тест", "industry": "Finance",
        })
        self.assertIn("New Corp".encode(), r.data)

    def test_admin_full_workflow_cycle(self):
        # Draft → In Review
        r = self._workflow("submit")
        self.assertEqual(r.status_code, 200)
        self._assert_risk_status("In Review")

        # In Review → Approved
        r = self._workflow("approve")
        self._assert_risk_status("Approved")

        # Approved → In Progress
        r = self._workflow("start")
        self._assert_risk_status("In Progress")

        # In Progress → Closed
        r = self._workflow("close")
        self._assert_risk_status("Closed")

    def test_admin_can_return_risk(self):
        self._workflow("submit")
        self._workflow("approve")
        r = self._workflow("return", "Нужна доработка")
        self._assert_risk_status("Returned")

    def test_admin_can_resubmit_after_return(self):
        self._workflow("submit")
        self._workflow("approve")
        self._workflow("return")
        r = self._workflow("submit")
        self._assert_risk_status("In Review")

    def test_admin_can_add_risk(self):
        r = self._post("/process_risks/add", {
            "process_id": self.process_id,
            "subprocess_id": self.subprocess_id,
            "risk_description": "Тест от admin",
            "probability": "2",
            "vulnerability_level": "2",
            "impact": "3",
            "control_effectiveness": "0.2",
            "status": "Draft",
        })
        self.assertEqual(r.status_code, 200)

    def test_admin_can_add_recommendation(self):
        r = self._post("/risk_treatments/add", {
            "process_risk_id": self.risk_id,
            "title": "Внедрить MFA",
            "description": "Детальное описание рекомендации",
            "treatment_type": "Reduce",
            "owner": "CISO",
            "progress": "0",
            "status": "Planned",
        })
        self.assertEqual(r.status_code, 200)

    def test_admin_csv_export(self):
        r = self.client.get("/process_risks/export.csv")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/csv", r.content_type)

    def _assert_risk_status(self, expected: str):
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            row = c.fetchone()
            self.assertIsNotNone(row, "Риск не найден")
            self.assertEqual(row[0], expected, f"Ожидали статус {expected}, получили {row[0]}")


# ===========================================================================
# 3. РОЛЬ: RISK_MANAGER — управление рисками, утверждение
# ===========================================================================

class TestRiskManagerRole(BaseRoleTest):

    def setUp(self):
        super().setUp()
        self._login("risk_manager")

    def test_risk_manager_sees_key_pages(self):
        for path in ["/dashboard", "/processes", "/process_risks",
                     "/risk_treatments", "/risk_workflow", "/compliance"]:
            self._get_200(path, f"risk_manager должен видеть {path}")

    def test_risk_manager_cannot_access_users_admin_page(self):
        r = self.client.get("/users")
        # Должен получить редирект (403 или 302 на /), не 200
        self.assertNotEqual(r.status_code, 200, "risk_manager не должен видеть /users")

    def test_risk_manager_can_approve_workflow(self):
        self._set_risk_status("In Review")
        r = self._workflow("approve")
        self.assertEqual(r.status_code, 200)
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            self.assertEqual(c.fetchone()[0], "Approved")

    def test_risk_manager_can_close_risk(self):
        self._set_risk_status("In Progress")
        self._workflow("close")
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            self.assertEqual(c.fetchone()[0], "Closed")

    def test_risk_manager_can_return_risk(self):
        self._set_risk_status("In Review")
        self._workflow("return", "Нужны уточнения")
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            self.assertEqual(c.fetchone()[0], "Returned")

    def test_risk_manager_cannot_submit_from_approved(self):
        self._set_risk_status("Approved")
        r = self._workflow("submit")
        # submit невозможен из Approved — статус не должен измениться
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            self.assertEqual(c.fetchone()[0], "Approved")

    def test_risk_manager_can_add_risk(self):
        r = self._post("/process_risks/add", {
            "process_id": self.process_id,
            "subprocess_id": self.subprocess_id,
            "risk_description": "Риск от risk_manager",
            "probability": "2",
            "vulnerability_level": "1",
            "impact": "2",
            "control_effectiveness": "0",
            "status": "Draft",
        })
        self.assertEqual(r.status_code, 200)

    def test_risk_manager_sees_responsibility_matrix(self):
        self._get_200("/responsibility_matrix")

    def test_risk_manager_sees_operational_analytics(self):
        self._get_200("/operational_analytics")


# ===========================================================================
# 4. РОЛЬ: PROCESS_OWNER — только свои процессы
# ===========================================================================

class TestProcessOwnerRole(BaseRoleTest):

    def setUp(self):
        super().setUp()
        self._login("process_owner")

    def test_process_owner_sees_main_pages(self):
        for path in ["/dashboard", "/processes", "/process_risks",
                     "/risk_treatments", "/my_tasks"]:
            self._get_200(path, f"process_owner должен видеть {path}")

    def test_process_owner_cannot_access_users(self):
        r = self.client.get("/users")
        self.assertNotEqual(r.status_code, 200)

    def test_process_owner_sees_own_process(self):
        r = self._get_200(f"/processes/{self.process_id}")
        self.assertIn("Incident Management".encode(), r.data)

    def test_process_owner_can_submit_risk(self):
        r = self._workflow("submit")
        self.assertEqual(r.status_code, 200)
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            self.assertEqual(c.fetchone()[0], "In Review")

    def test_process_owner_cannot_approve(self):
        self._set_risk_status("In Review")
        self._workflow("approve")
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            # Не должен смочь одобрить — статус остаётся In Review
            self.assertEqual(c.fetchone()[0], "In Review")

    def test_process_owner_can_start_treatment(self):
        self._set_risk_status("Approved")
        self._workflow("start")
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            self.assertEqual(c.fetchone()[0], "In Progress")

    def test_process_owner_can_add_risk(self):
        r = self._post("/process_risks/add", {
            "process_id": self.process_id,
            "subprocess_id": self.subprocess_id,
            "risk_description": "Добавлено владельцем",
            "probability": "1",
            "vulnerability_level": "1",
            "impact": "1",
            "control_effectiveness": "0",
            "status": "Draft",
        })
        self.assertEqual(r.status_code, 200)

    def test_process_owner_sees_bpmn_viewer(self):
        r = self.client.get(f"/api/process_bpmn/{self.process_id}")
        self.assertEqual(r.status_code, 200)

    def test_process_owner_cannot_close_risk(self):
        self._set_risk_status("In Progress")
        self._workflow("close")
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            # process_owner не имеет права close
            self.assertEqual(c.fetchone()[0], "In Progress")


# ===========================================================================
# 5. РОЛЬ: EXPERT — оценка, отправка на согласование
# ===========================================================================

class TestExpertRole(BaseRoleTest):

    def setUp(self):
        super().setUp()
        self._login("expert")

    def test_expert_sees_main_pages(self):
        for path in ["/dashboard", "/processes", "/process_risks",
                     "/risk_workflow", "/my_tasks", "/methodology"]:
            self._get_200(path, f"expert должен видеть {path}")

    def test_expert_cannot_access_users(self):
        r = self.client.get("/users")
        self.assertNotEqual(r.status_code, 200)

    def test_expert_can_submit_risk(self):
        r = self._workflow("submit")
        self.assertEqual(r.status_code, 200)
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            self.assertEqual(c.fetchone()[0], "In Review")

    def test_expert_cannot_approve(self):
        self._set_risk_status("In Review")
        self._workflow("approve")
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            self.assertEqual(c.fetchone()[0], "In Review")

    def test_expert_cannot_start_treatment(self):
        self._set_risk_status("Approved")
        self._workflow("start")
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            self.assertEqual(c.fetchone()[0], "Approved")

    def test_expert_cannot_add_risk_via_route(self):
        r = self.client.get("/process_risks/add")
        self.assertNotEqual(r.status_code, 200, "expert не должен иметь доступ к форме добавления")

    def test_expert_sees_process_detail_and_ai(self):
        self._get_200(f"/processes/{self.process_id}")
        self._get_200(f"/ai_analysis/{self.process_id}")

    def test_expert_sees_compliance(self):
        self._get_200("/compliance")

    def test_expert_sees_bpmn_api(self):
        r = self.client.get(f"/api/process_bpmn/{self.process_id}")
        self.assertEqual(r.status_code, 200)


# ===========================================================================
# 6. РОЛЬ: AUDITOR — только чтение
# ===========================================================================

class TestAuditorRole(BaseRoleTest):

    def setUp(self):
        super().setUp()
        self._login("auditor")

    def test_auditor_sees_all_read_pages(self):
        # audit_log и data_quality — только admin (@admin_required)
        pages = [
            "/dashboard",
            "/processes",
            f"/processes/{self.process_id}",
            "/process_risks",
            "/risk_treatments",
            "/risk_workflow",
            "/responsibility_matrix",
            "/compliance",
            "/operational_analytics",
            "/methodology",
            f"/process_report/{self.process_id}",
        ]
        for path in pages:
            self._get_200(path, f"auditor должен видеть {path}")

    def test_auditor_cannot_access_admin_only_pages(self):
        for path in ["/audit_log", "/data_quality", "/users", "/experts"]:
            r = self.client.get(path)
            self.assertNotEqual(r.status_code, 200, f"auditor не должен видеть {path}")

    def test_auditor_cannot_access_users(self):
        r = self.client.get("/users")
        self.assertNotEqual(r.status_code, 200)

    def test_auditor_cannot_add_risk(self):
        r = self.client.get("/process_risks/add")
        self.assertNotEqual(r.status_code, 200)

    def test_auditor_cannot_submit_workflow(self):
        self._workflow("submit")
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            self.assertEqual(c.fetchone()[0], "Draft", "auditor не должен менять статус")

    def test_auditor_cannot_add_company(self):
        r = self._post("/companies/add", {
            "name": "Auditor Corp", "description": "Тест", "industry": "Finance",
        })
        # Должен получить редирект или 403, но не успешно создать
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM companies WHERE name='Auditor Corp'")
            count = c.fetchone()[0]
            self.assertEqual(count, 0, "auditor не должен создавать компании")

    def test_auditor_sees_csv_export(self):
        r = self.client.get("/process_risks/export.csv")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/csv", r.content_type)

    def test_auditor_sees_bpmn_api(self):
        r = self.client.get(f"/api/process_bpmn/{self.process_id}")
        self.assertEqual(r.status_code, 200)

    def test_auditor_cannot_save_bpmn(self):
        r = self._post_json(
            f"/api/process_bpmn/{self.process_id}",
            {"nodes": [], "edges": []},
        )
        # Должен получить 403 или редирект
        self.assertNotEqual(r.status_code, 200, "auditor не должен сохранять BPMN")


# ===========================================================================
# 7. WORKFLOW — полный цикл и граничные случаи
# ===========================================================================

class TestWorkflowStateMachine(BaseRoleTest):

    def setUp(self):
        super().setUp()
        self._login("admin")

    def _status(self):
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT status FROM process_risks WHERE id=?", (self.risk_id,))
            return c.fetchone()[0]

    def test_initial_status_is_draft(self):
        self.assertEqual(self._status(), "Draft")

    def test_full_cycle_draft_to_closed(self):
        self._workflow("submit")
        self.assertEqual(self._status(), "In Review")
        self._workflow("approve")
        self.assertEqual(self._status(), "Approved")
        self._workflow("start")
        self.assertEqual(self._status(), "In Progress")
        self._workflow("close")
        self.assertEqual(self._status(), "Closed")

    def test_return_and_resubmit_cycle(self):
        self._workflow("submit")
        self._workflow("return", "Уточните описание")
        self.assertEqual(self._status(), "Returned")
        self._workflow("submit")
        self.assertEqual(self._status(), "In Review")

    def test_cannot_close_from_draft(self):
        self._workflow("close")
        self.assertEqual(self._status(), "Draft", "close из Draft недопустим")

    def test_cannot_start_from_draft(self):
        self._workflow("start")
        self.assertEqual(self._status(), "Draft", "start из Draft недопустим")

    def test_cannot_approve_from_draft(self):
        self._workflow("approve")
        self.assertEqual(self._status(), "Draft", "approve из Draft недопустим")

    def test_workflow_history_recorded(self):
        self._workflow("submit", "Первичная оценка")
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute(
                "SELECT COUNT(*) FROM process_risk_workflow WHERE process_risk_id=?",
                (self.risk_id,),
            )
            count = c.fetchone()[0]
        self.assertGreater(count, 0, "История workflow должна записываться")

    def test_workflow_history_captures_to_status(self):
        self._workflow("submit")
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute(
                "SELECT to_status FROM process_risk_workflow WHERE process_risk_id=? ORDER BY id DESC LIMIT 1",
                (self.risk_id,),
            )
            row = c.fetchone()
        self.assertEqual(row[0], "In Review")

    def test_risk_manager_cannot_submit_as_workflow(self):
        self._logout()
        self._login("risk_manager")
        self._set_risk_status("Approved")
        self._workflow("submit")
        self.assertEqual(self._status(), "Approved")

    def test_expert_submit_allowed(self):
        self._logout()
        self._login("expert")
        self._workflow("submit")
        self.assertEqual(self._status(), "In Review")

    def test_auditor_cannot_change_workflow(self):
        self._logout()
        self._login("auditor")
        self._workflow("submit")
        self.assertEqual(self._status(), "Draft")

    def _logout(self):
        self.client.get("/logout")


# ===========================================================================
# 8. BPMN
# ===========================================================================

class TestBPMN(BaseRoleTest):

    def setUp(self):
        super().setUp()
        self._login("admin")

    def test_bpmn_get_returns_json_with_nodes_edges(self):
        r = self.client.get(f"/api/process_bpmn/{self.process_id}")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        bpmn = data["bpmn"]
        self.assertIn("nodes", bpmn)
        self.assertIn("edges", bpmn)

    def test_bpmn_save_replaces_not_accumulates(self):
        payload = {
            "nodes": [
                {"id": "s", "type": "start", "label": "Start"},
                {"id": "e", "type": "end",   "label": "End"},
            ],
            "edges": [{"from": "s", "to": "e"}],
        }
        self.client.post(f"/api/process_bpmn/{self.process_id}", json=payload)
        self.client.post(f"/api/process_bpmn/{self.process_id}", json=payload)

        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM process_bpmn WHERE process_id=?", (self.process_id,))
            count = c.fetchone()[0]
        self.assertEqual(count, 1, "BPMN должен хранить ровно одну запись на процесс")

    def test_bpmn_empty_process_returns_empty_model(self):
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO processes (company_id,name,process_type,owner) VALUES (?,?,?,?)",
                (1, "Empty Process", "Security", "Nobody"),
            )
            new_pid = c.lastrowid
            conn.commit()
        r = self.client.get(f"/api/process_bpmn/{new_pid}")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        # Нет записи BPMN — API возвращает пустую модель или null
        bpmn = data.get("bpmn")
        if bpmn is not None:
            # Если возвращает объект — должен быть пустым (нет узлов)
            self.assertEqual(bpmn.get("nodes", []), [])

    def test_bpmn_viewer_on_process_detail(self):
        r = self.client.get(f"/processes/{self.process_id}")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"BPMN", r.data)

    def test_bpmn_edit_page_accessible_by_admin(self):
        r = self.client.get(f"/processes/{self.process_id}/bpmn")
        self.assertEqual(r.status_code, 200)

    def test_bpmn_save_invalid_json_handled(self):
        r = self.client.post(
            f"/api/process_bpmn/{self.process_id}",
            data="not-json",
            content_type="application/json",
        )
        self.assertIn(r.status_code, (200, 400))


# ===========================================================================
# 9. ФОРМУЛА РАСЧЁТА РИСКА
# ===========================================================================

class TestRiskFormula(BaseRoleTest):

    def test_potentiality_formula(self):
        from services.risk_service import calculate_event_potentiality
        self.assertAlmostEqual(calculate_event_potentiality(2.5, 2.0), 3.5)
        self.assertEqual(calculate_event_potentiality(0.5, 0.5), 0.0)  # max(P+V-1,0)

    def test_full_metrics_low_risk(self):
        from services.risk_service import calculate_process_risk_metrics, classify_numeric_risk
        m = calculate_process_risk_metrics(1, 1, 1, 1.0, 0, 5)
        self.assertEqual(m["residual_risk"], 0.0)
        self.assertEqual(classify_numeric_risk(m["residual_risk"]), "Низкий")

    def test_full_metrics_high_risk(self):
        from services.risk_service import calculate_process_risk_metrics, classify_numeric_risk
        m = calculate_process_risk_metrics(3, 3, 9, 0.0, 0, 9)
        self.assertGreater(m["residual_risk"], 7)
        self.assertEqual(classify_numeric_risk(m["residual_risk"]), "Высокий")

    def test_residual_lower_than_initial_when_control_present(self):
        from services.risk_service import calculate_process_risk_metrics
        no_ctrl = calculate_process_risk_metrics(2.5, 2, 3, 0.0, 0, 5)
        with_ctrl = calculate_process_risk_metrics(2.5, 2, 3, 0.5, 0, 5)
        self.assertLess(with_ctrl["residual_risk"], no_ctrl["residual_risk"])

    def test_calculate_risk_function_boundary(self):
        # Минимальная вероятность и контроль полный → остаточный = 0
        _, residual, _, _ = app_module.calculate_risk(1, 1, 1.0)
        self.assertEqual(residual, 0)

    def test_risk_levels_boundaries(self):
        from services.risk_service import classify_numeric_risk
        self.assertEqual(classify_numeric_risk(0), "Низкий")
        self.assertEqual(classify_numeric_risk(3.9), "Низкий")
        self.assertEqual(classify_numeric_risk(4.0), "Средний")
        self.assertEqual(classify_numeric_risk(6.9), "Средний")
        self.assertEqual(classify_numeric_risk(7.0), "Высокий")
        self.assertEqual(classify_numeric_risk(9.0), "Высокий")


# ===========================================================================
# 10. AI-РЕКОМЕНДАЦИИ
# ===========================================================================

class TestAIRecommender(BaseRoleTest):

    def test_no_control_triggers_recommendation(self):
        from ai.risk_recommender import recommend_process_risk
        rec = recommend_process_risk(7.5, 0.0, None, "Высокий")
        self.assertIn("назначить контрольную меру", rec)

    def test_high_risk_triggers_priority(self):
        from ai.risk_recommender import recommend_process_risk
        rec = recommend_process_risk(8.0, 0.2, 1, "Высокий")
        self.assertIn("приоритетного", rec)

    def test_low_risk_acceptable_message(self):
        from ai.risk_recommender import recommend_process_risk
        rec = recommend_process_risk(1.0, 0.8, 1, "Низкий")
        self.assertIn("допустим", rec.lower())

    def test_process_analysis_top_risk(self):
        from ai.risk_recommender import analyze_process_risks
        risks = [
            {"subprocess_name": "A", "threat_name": "T1", "vulnerability_name": "V1",
             "control_name": None, "control_effectiveness": 0.1,
             "residual_risk": 8.0, "risk_level": "Высокий"},
            {"subprocess_name": "B", "threat_name": "T1", "vulnerability_name": "V1",
             "control_name": "C1", "control_effectiveness": 0.6,
             "residual_risk": 3.0, "risk_level": "Низкий"},
        ]
        result = analyze_process_risks(risks)
        self.assertEqual(result["top_risk"]["subprocess_name"], "A")
        self.assertEqual(result["rating"], "High")
        self.assertEqual(len(result["missing_control_risks"]), 1)

    def test_ai_analysis_page_returns_200(self):
        self._login("admin")
        r = self.client.get(f"/ai_analysis/{self.process_id}")
        self.assertEqual(r.status_code, 200)


# ===========================================================================
# 11. ДАННЫЕ — создание через маршруты
# ===========================================================================

class TestDataCreation(BaseRoleTest):

    def setUp(self):
        super().setUp()
        self._login("admin")

    def test_create_subprocess(self):
        r = self._post("/subprocesses/add", {
            "process_id": self.process_id,
            "name": "Новый подпроцесс",
            "responsible_person": "Аналитик",
            "used_systems": "SIEM",
            "order_index": "2",
        })
        self.assertEqual(r.status_code, 200)
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM subprocesses WHERE name='Новый подпроцесс'")
            self.assertEqual(c.fetchone()[0], 1)

    def test_create_expert(self):
        r = self._post("/experts/add", {"name": "Иванов И.И."})
        self.assertEqual(r.status_code, 200)

    def test_create_recommendation_for_risk(self):
        r = self._post("/risk_treatments/add", {
            "process_risk_id": self.risk_id,
            "title": "Внедрить SIEM-правило",
            "description": "Настроить корреляционные правила для обнаружения атак",
            "treatment_type": "Reduce",
            "owner": "CISO",
            "progress": "10",
            "status": "Planned",
        })
        self.assertEqual(r.status_code, 200)

    def test_process_report_renders(self):
        r = self.client.get(f"/process_report/{self.process_id}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Incident Management".encode(), r.data)

    def test_company_report_zip(self):
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT id FROM companies LIMIT 1")
            cid = c.fetchone()[0]
        r = self.client.get(f"/companies/{cid}/report.zip")
        self.assertIn(r.status_code, (200, 302, 404))


# ===========================================================================
# 12. РАЗГРАНИЧЕНИЕ ВИДИМОСТИ (process_owner видит только своё)
# ===========================================================================

class TestDataVisibility(BaseRoleTest):

    def setUp(self):
        super().setUp()
        # Создаём второй процесс без привязки к process_owner
        with app_module.get_db_connection() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO companies (name, description, industry) VALUES (?,?,?)",
                ("Other Corp", "Другая компания", "Finance"),
            )
            other_cid = c.lastrowid
            c.execute(
                "INSERT INTO processes (company_id,name,process_type,owner) VALUES (?,?,?,?)",
                (other_cid, "Foreign Process", "Finance", "Someone Else"),
            )
            self.other_process_id = c.lastrowid
            conn.commit()

    def test_admin_sees_all_processes(self):
        self._login("admin")
        r = self._get_200("/processes")
        self.assertIn("Incident Management".encode(), r.data)
        self.assertIn("Foreign Process".encode(), r.data)

    def test_auditor_sees_all_processes(self):
        self._login("auditor")
        r = self._get_200("/processes")
        self.assertIn("Incident Management".encode(), r.data)

    def test_process_owner_process_list_accessible(self):
        self._login("process_owner")
        r = self._get_200("/processes")
        # Список открывается (пусть даже пуст — без ошибки)
        self.assertEqual(r.status_code, 200)

    def test_risk_manager_sees_all_risks(self):
        self._login("risk_manager")
        r = self._get_200("/process_risks")
        self.assertEqual(r.status_code, 200)


# ===========================================================================
# ENTRY POINT
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
