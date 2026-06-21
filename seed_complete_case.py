import json

from app import get_db_connection
from ai.risk_recommender import recommend_process_risk
from services.risk_service import calculate_process_risk_metrics, classify_numeric_risk


def get_or_create(cursor, table, name, extra_columns=None, extra_values=None):
    cursor.execute(f"SELECT id FROM {table} WHERE name = ?", (name,))
    row = cursor.fetchone()
    if row:
        return row[0]
    columns = ["name"] + (extra_columns or [])
    placeholders = ", ".join(["?"] * len(columns))
    cursor.execute(
        f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
        (name, *(extra_values or [])),
    )
    return cursor.lastrowid


def upsert_company(cursor):
    name = "FinTech Demo"
    cursor.execute("SELECT id FROM companies WHERE name = ?", (name,))
    row = cursor.fetchone()
    if row:
        company_id = row[0]
        cursor.execute(
            "UPDATE companies SET description = ?, industry = ? WHERE id = ?",
            ("Демонстрационная финтех-компания для полного кейса process risk analysis.", "Financial services", company_id),
        )
        return company_id
    cursor.execute(
        "INSERT INTO companies (name, description, industry) VALUES (?, ?, ?)",
        (name, "Демонстрационная финтех-компания для полного кейса process risk analysis.", "Financial services"),
    )
    return cursor.lastrowid


def upsert_process(cursor, company_id):
    name = "Обработка фишингового инцидента"
    cursor.execute("SELECT id FROM processes WHERE name = ?", (name,))
    row = cursor.fetchone()
    values = (
        company_id,
        name,
        "Полный кейс: обнаружение фишинга, проверка письма, блокировка IOC, сброс учетных данных, уведомление пользователей и закрытие инцидента.",
        "Information Security",
        "SOC Manager",
        "Жалоба пользователя, EDR/SIEM событие, подозрительное письмо",
        "Заблокированные IOC, защищенная учетная запись, отчет и lessons learned",
        "Политика ИБ, регламент реагирования, требования к защите персональных данных",
        "SOC, SIEM, EDR, Email Gateway, IAM, Service Desk",
    )
    if row:
        process_id = row[0]
        cursor.execute(
            """
            UPDATE processes
            SET company_id = ?, name = ?, description = ?, process_type = ?, owner = ?,
                input_data = ?, output_data = ?, regulations = ?, resources = ?
            WHERE id = ?
            """,
            values + (process_id,),
        )
        return process_id
    cursor.execute(
        """
        INSERT INTO processes (
            company_id, name, description, process_type, owner, input_data, output_data, regulations, resources
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        values,
    )
    return cursor.lastrowid


def upsert_assets(cursor, process_id):
    assets = [
        ("Email Gateway", "Фильтрация и карантин фишинговых писем"),
        ("SIEM", "Корреляция событий и контроль IOC"),
        ("EDR", "Проверка рабочей станции пользователя"),
        ("IAM", "Сброс пароля и отзыв активных сессий"),
        ("Service Desk", "Коммуникация с пользователями и фиксация обращений"),
    ]
    asset_ids = []
    for name, role in assets:
        asset_id = get_or_create(cursor, "assets", name)
        asset_ids.append(asset_id)
        cursor.execute(
            "SELECT id FROM process_assets WHERE process_id = ? AND asset_id = ?",
            (process_id, asset_id),
        )
        row = cursor.fetchone()
        if row:
            cursor.execute("UPDATE process_assets SET role_in_process = ? WHERE id = ?", (role, row[0]))
        else:
            cursor.execute(
                "INSERT INTO process_assets (process_id, asset_id, role_in_process) VALUES (?, ?, ?)",
                (process_id, asset_id, role),
            )
    return asset_ids


def upsert_subprocesses(cursor, process_id):
    subprocesses = [
        ("Получение сообщения о фишинге", "Жалоба пользователя или событие Email Gateway", "Заявка SOC", "SOC Analyst", "Service Desk, Email Gateway"),
        ("Первичная triage-проверка", "Заявка SOC", "Классификация подозрительного письма", "SOC Analyst", "SIEM, Email Gateway"),
        ("Анализ письма и вложений", "Подозрительное письмо", "IOC и verdict", "Malware Analyst", "Sandbox, EDR, Email Gateway"),
        ("Блокировка IOC и письма", "IOC и verdict", "Заблокированные домены, URL, hash и письмо", "Detection Engineer", "SIEM, Email Gateway, EDR"),
        ("Сброс учетных данных", "Подтвержденный компромисс", "Сброшенный пароль и отозванные сессии", "IAM Administrator", "IAM, EDR"),
        ("Уведомление и закрытие", "Итоги реагирования", "Отчет, рекомендации, закрытая заявка", "SOC Manager", "Service Desk, SIEM"),
    ]
    ids = {}
    for index, (name, input_data, output_data, responsible, systems) in enumerate(subprocesses, 1):
        cursor.execute("SELECT id FROM subprocesses WHERE process_id = ? AND name = ?", (process_id, name))
        row = cursor.fetchone()
        values = (
            process_id,
            name,
            f"Кейс phishing incident response: {name}.",
            input_data,
            output_data,
            responsible,
            systems,
            index,
        )
        if row:
            subprocess_id = row[0]
            cursor.execute(
                """
                UPDATE subprocesses
                SET process_id = ?, name = ?, description = ?, input_data = ?, output_data = ?,
                    responsible_person = ?, used_systems = ?, order_index = ?
                WHERE id = ?
                """,
                values + (subprocess_id,),
            )
        else:
            cursor.execute(
                """
                INSERT INTO subprocesses (
                    process_id, name, description, input_data, output_data, responsible_person, used_systems, order_index
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            subprocess_id = cursor.lastrowid
        ids[name] = subprocess_id
    return ids


def upsert_bpmn(cursor, process_id, subprocess_ids):
    nodes = [
        {"id": "start", "type": "start", "label": "Фишинг обнаружен", "x": 70, "y": 260},
        {"id": "intake", "type": "task", "label": "Получение сообщения", "subprocess_id": subprocess_ids["Получение сообщения о фишинге"], "x": 220, "y": 250},
        {"id": "triage", "type": "task", "label": "Первичная triage-проверка", "subprocess_id": subprocess_ids["Первичная triage-проверка"], "x": 430, "y": 250},
        {"id": "gateway", "type": "gateway", "label": "Фишинг подтвержден?", "subprocess_id": subprocess_ids["Первичная triage-проверка"], "x": 670, "y": 245},
        {"id": "analysis", "type": "task", "label": "Анализ письма и вложений", "subprocess_id": subprocess_ids["Анализ письма и вложений"], "x": 880, "y": 145},
        {"id": "block_ioc", "type": "task", "label": "Блокировка IOC и письма", "subprocess_id": subprocess_ids["Блокировка IOC и письма"], "x": 1110, "y": 145},
        {"id": "reset_account", "type": "task", "label": "Сброс учетных данных", "subprocess_id": subprocess_ids["Сброс учетных данных"], "x": 1110, "y": 330},
        {"id": "false_positive", "type": "task", "label": "Закрыть как false positive", "subprocess_id": subprocess_ids["Уведомление и закрытие"], "x": 880, "y": 430},
        {"id": "close", "type": "task", "label": "Уведомление и закрытие", "subprocess_id": subprocess_ids["Уведомление и закрытие"], "x": 1360, "y": 240},
        {"id": "end", "type": "end", "label": "Кейс закрыт", "x": 1600, "y": 260},
    ]
    edges = [
        {"from": "start", "to": "intake"},
        {"from": "intake", "to": "triage"},
        {"from": "triage", "to": "gateway"},
        {"from": "gateway", "to": "analysis", "label": "Да"},
        {"from": "analysis", "to": "block_ioc"},
        {"from": "analysis", "to": "reset_account"},
        {"from": "block_ioc", "to": "close"},
        {"from": "reset_account", "to": "close"},
        {"from": "gateway", "to": "false_positive", "label": "Нет"},
        {"from": "false_positive", "to": "close"},
        {"from": "close", "to": "end"},
    ]
    model = json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False)
    cursor.execute("SELECT id FROM process_bpmn WHERE process_id = ? ORDER BY id DESC LIMIT 1", (process_id,))
    row = cursor.fetchone()
    if row:
        cursor.execute("UPDATE process_bpmn SET bpmn_json = ? WHERE id = ?", (model, row[0]))
    else:
        cursor.execute("INSERT INTO process_bpmn (process_id, bpmn_json) VALUES (?, ?)", (process_id, model))


def upsert_risks(cursor, process_id, subprocess_ids, asset_ids):
    scenarios = [
        {
            "sp": "Получение сообщения о фишинге",
            "asset": 4,
            "threat": "Фишинговое письмо не зарегистрировано",
            "vulnerability": "Пользователи не знают единый канал сообщения о фишинге",
            "control": "Кнопка Report Phishing и triage-очередь Service Desk",
            "risk": "Пользователь пересылает письмо поздно или не тем каналом, SOC теряет время на реакцию.",
            "p": 2.3,
            "v": 2.2,
            "i": 2.5,
            "eff": 0.5,
            "cost": 2,
            "status": "Mitigated",
            "risk_owner": "SOC Manager",
            "mitigation_owner": "Service Desk Lead",
            "due": "2026-05-18",
            "source": "Expert",
            "confidence": "High",
            "evidence": "Проведен пилот кнопки Report Phishing, время регистрации обращения снижено.",
        },
        {
            "sp": "Первичная triage-проверка",
            "asset": 1,
            "threat": "Ошибочная классификация фишинга",
            "vulnerability": "Нет чек-листа triage и критериев подтверждения",
            "control": "Triage checklist и SLA первичной проверки 15 минут",
            "risk": "Аналитик ошибочно закрывает фишинговое письмо как безопасное.",
            "p": 2.6,
            "v": 2.7,
            "i": 2.8,
            "eff": 0.42,
            "cost": 2,
            "status": "In progress",
            "risk_owner": "SOC Shift Lead",
            "mitigation_owner": "SOC Analyst",
            "due": "2026-05-22",
            "source": "Expert",
            "confidence": "Medium",
            "evidence": "Выборочная проверка закрытых обращений за месяц выявила ошибки классификации.",
        },
        {
            "sp": "Анализ письма и вложений",
            "asset": 2,
            "threat": "Вредоносное вложение не выявлено",
            "vulnerability": "Не все вложения отправляются в sandbox/EDR",
            "control": "Автоматическая отправка вложений в sandbox и EDR enrichment",
            "risk": "Скрытое вредоносное вложение проходит без анализа и приводит к компрометации рабочей станции.",
            "p": 2.7,
            "v": 2.9,
            "i": 3.0,
            "eff": 0.35,
            "cost": 5,
            "status": "Mitigation planned",
            "risk_owner": "Malware Analyst",
            "mitigation_owner": "EDR Engineer",
            "due": "2026-06-05",
            "source": "System calculation",
            "confidence": "High",
            "evidence": "Sandbox coverage report показывает неполное покрытие типов вложений.",
        },
        {
            "sp": "Блокировка IOC и письма",
            "asset": 0,
            "threat": "IOC остаются доступными пользователям",
            "vulnerability": "Блокировки в Email Gateway, SIEM и EDR выполняются вручную",
            "control": "Автоматизированный playbook блокировки IOC",
            "risk": "Фишинговый URL остается доступным, пользователи продолжают переходить по ссылке.",
            "p": 2.8,
            "v": 2.6,
            "i": 2.9,
            "eff": 0.55,
            "cost": 4,
            "status": "Approved",
            "risk_owner": "Detection Engineer",
            "mitigation_owner": "SOAR Engineer",
            "due": "2026-06-12",
            "source": "Manual",
            "confidence": "Medium",
            "evidence": "Tabletop exercise показал задержку между verdict и блокировкой IOC.",
        },
        {
            "sp": "Сброс учетных данных",
            "asset": 3,
            "threat": "Компрометированная учетная запись остается активной",
            "vulnerability": "Нет автоматического отзыва сессий после подтверждения компромисса",
            "control": "IAM workflow: reset password, revoke sessions, force MFA",
            "risk": "Атакующий продолжает использовать активную сессию после сброса пароля.",
            "p": 2.5,
            "v": 2.5,
            "i": 3.0,
            "eff": 0.58,
            "cost": 3,
            "status": "In progress",
            "risk_owner": "IAM Administrator",
            "mitigation_owner": "IAM Administrator",
            "due": "2026-05-29",
            "source": "Expert",
            "confidence": "High",
            "evidence": "IAM audit показал отсутствие обязательного session revoke в старом runbook.",
        },
        {
            "sp": "Уведомление и закрытие",
            "asset": 4,
            "threat": "Пользователи повторяют ошибку",
            "vulnerability": "Нет targeted awareness после инцидента",
            "control": "Targeted awareness и post-incident action items",
            "risk": "Команда закрывает инцидент без обучения затронутых пользователей и контроля action items.",
            "p": 2.1,
            "v": 2.0,
            "i": 2.3,
            "eff": 0.62,
            "cost": 2,
            "status": "Mitigated",
            "risk_owner": "SOC Manager",
            "mitigation_owner": "Security Awareness Lead",
            "due": "2026-05-24",
            "source": "Expert",
            "confidence": "Medium",
            "evidence": "После закрытия кейса создан targeted awareness template и список action items.",
        },
    ]

    for scenario in scenarios:
        subprocess_id = subprocess_ids[scenario["sp"]]
        asset_id = asset_ids[scenario["asset"]]
        threat_id = get_or_create(cursor, "threats", scenario["threat"])
        vulnerability_id = get_or_create(cursor, "vulnerabilities", scenario["vulnerability"], ["category"], ["Phishing process"])
        control_id = get_or_create(cursor, "control_measures", scenario["control"])
        metrics = calculate_process_risk_metrics(
            scenario["p"],
            scenario["v"],
            scenario["i"],
            scenario["eff"],
            scenario["cost"],
            8,
        )
        category = classify_numeric_risk(metrics["residual_risk"])
        recommendation = recommend_process_risk(metrics["residual_risk"], scenario["eff"], control_id, category, scenario["v"])
        recommendation = f"{recommendation} Контроль '{scenario['control']}' снижает риск с {metrics['risk_level']:.2f} до {metrics['residual_risk']:.2f}."

        cursor.execute(
            "SELECT id FROM process_risks WHERE process_id = ? AND subprocess_id = ? ORDER BY id LIMIT 1",
            (process_id, subprocess_id),
        )
        row = cursor.fetchone()
        values = (
            process_id,
            subprocess_id,
            asset_id,
            threat_id,
            vulnerability_id,
            control_id,
            scenario["risk"],
            scenario["p"],
            scenario["v"],
            scenario["i"],
            metrics["risk_level"],
            scenario["eff"],
            metrics["residual_risk"],
            metrics["risk_level"],
            category,
            scenario["cost"],
            metrics["risk_reduction"],
            metrics["priority"],
            recommendation,
            scenario["status"],
            scenario["risk_owner"],
            scenario["mitigation_owner"],
            scenario["due"],
            scenario["source"],
            scenario["confidence"],
            scenario["evidence"],
            "2026-05-05",
        )
        if row:
            cursor.execute(
                """
                UPDATE process_risks
                SET process_id = ?, subprocess_id = ?, asset_id = ?, threat_id = ?, vulnerability_id = ?,
                    control_measure_id = ?, risk_description = ?, probability = ?, vulnerability_level = ?,
                    impact = ?, initial_risk = ?, control_effectiveness = ?, residual_risk = ?, risk_level = ?,
                    risk_category = ?, cost = ?, risk_reduction = ?, priority = ?, ai_recommendation = ?,
                    status = ?, risk_owner = ?, mitigation_owner = ?, due_date = ?, assessment_source = ?,
                    confidence = ?, evidence = ?, last_reviewed_at = ?
                WHERE id = ?
                """,
                values + (row[0],),
            )
        else:
            cursor.execute(
                """
                INSERT INTO process_risks (
                    process_id, subprocess_id, asset_id, threat_id, vulnerability_id, control_measure_id,
                    risk_description, probability, vulnerability_level, impact, initial_risk, control_effectiveness,
                    residual_risk, risk_level, risk_category, cost, risk_reduction, priority, ai_recommendation,
                    status, risk_owner, mitigation_owner, due_date, assessment_source, confidence, evidence, last_reviewed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )


def upsert_expert_users(cursor):
    experts = ["SOC Expert", "Risk Methodologist"]
    expert_ids = []
    for name in experts:
        expert_ids.append(get_or_create(cursor, "experts", name))
    return expert_ids


def upsert_expert_assessments(cursor, process_id, expert_ids):
    cursor.execute('''
        SELECT pr.id, sp.order_index, pr.probability, pr.vulnerability_level, pr.impact, pr.control_effectiveness
        FROM process_risks pr
        JOIN subprocesses sp ON sp.id = pr.subprocess_id
        WHERE pr.process_id = ?
        ORDER BY sp.order_index
    ''', (process_id,))
    risks = cursor.fetchall()
    for risk_id, order_index, probability, vulnerability, impact, effectiveness in risks:
        for offset, expert_id in enumerate(expert_ids):
            adjusted_probability = max(0, min(3, (probability or 0) + (0.1 if offset == 0 else -0.1)))
            adjusted_vulnerability = max(0, min(3, (vulnerability or 0) + (0.05 if offset == 0 else -0.05)))
            adjusted_impact = max(0, (impact or 0) + (0.1 if order_index in (2, 3) and offset == 0 else 0))
            adjusted_effectiveness = max(0, min(1, (effectiveness or 0) + (0.03 if offset == 1 else -0.02)))
            confidence = "High" if order_index in (1, 3, 5) else "Medium"
            evidence = f"Экспертная оценка для phishing кейса, шаг {order_index}; использованы интервью SOC и evidence из risk register."
            cursor.execute(
                "SELECT id FROM process_risk_expert_assessments WHERE process_risk_id = ? AND expert_id = ?",
                (risk_id, expert_id),
            )
            row = cursor.fetchone()
            values = (
                risk_id,
                expert_id,
                adjusted_probability,
                adjusted_vulnerability,
                adjusted_impact,
                adjusted_effectiveness,
                confidence,
                evidence,
            )
            if row:
                cursor.execute(
                    """
                    UPDATE process_risk_expert_assessments
                    SET probability = ?, vulnerability_level = ?, impact = ?, control_effectiveness = ?,
                        confidence = ?, evidence = ?, created_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    values[2:] + (row[0],),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO process_risk_expert_assessments (
                        process_risk_id, expert_id, probability, vulnerability_level, impact,
                        control_effectiveness, confidence, evidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values,
                )
        from app import update_process_risk_from_expert_assessments
        update_process_risk_from_expert_assessments(cursor, risk_id)


def seed():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        company_id = upsert_company(cursor)
        process_id = upsert_process(cursor, company_id)
        asset_ids = upsert_assets(cursor, process_id)
        subprocess_ids = upsert_subprocesses(cursor, process_id)
        upsert_bpmn(cursor, process_id, subprocess_ids)
        upsert_risks(cursor, process_id, subprocess_ids, asset_ids)
        expert_ids = upsert_expert_users(cursor)
        upsert_expert_assessments(cursor, process_id, expert_ids)
        conn.commit()
    print(f"Полный кейс создан: process_id={process_id}")


if __name__ == "__main__":
    seed()
