import json

from app import calculate_risk, get_db_connection
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


def add_process_case(cursor, company_id, case):
    process_id = get_or_create(
        cursor,
        "processes",
        case["process"],
        ["company_id", "description", "process_type", "owner", "input_data", "output_data", "regulations", "resources"],
        [company_id, case["description"], case["type"], case["owner"], case["input"], case["output"], case["regulations"], case["resources"]],
    )

    asset_ids = []
    for asset_name, role in case["assets"]:
        asset_id = get_or_create(cursor, "assets", asset_name)
        asset_ids.append(asset_id)
        try:
            cursor.execute(
                "INSERT INTO process_assets (process_id, asset_id, role_in_process) VALUES (?, ?, ?)",
                (process_id, asset_id, role),
            )
        except Exception:
            pass

    subprocess_ids = []
    for index, subprocess_name in enumerate(case["subprocesses"], 1):
        cursor.execute("SELECT id FROM subprocesses WHERE process_id = ? AND name = ?", (process_id, subprocess_name))
        row = cursor.fetchone()
        if row:
            subprocess_ids.append(row[0])
            continue
        cursor.execute(
            """
            INSERT INTO subprocesses (process_id, name, description, responsible_person, used_systems, order_index)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (process_id, subprocess_name, f"Демо-подпроцесс: {subprocess_name}", case["owner"], ", ".join(name for name, _ in case["assets"]), index),
        )
        subprocess_ids.append(cursor.lastrowid)

    bpmn_json = case.get("bpmn") or {
        "nodes": [{"id": f"step{idx}", "type": "task", "label": name} for idx, name in enumerate(case["subprocesses"], 1)],
        "edges": [{"from": f"step{idx}", "to": f"step{idx + 1}"} for idx in range(1, len(case["subprocesses"]))],
    }
    cursor.execute("SELECT id FROM process_bpmn WHERE process_id = ? ORDER BY id DESC", (process_id,))
    bpmn_row = cursor.fetchone()
    if bpmn_row and case.get("update_bpmn"):
        cursor.execute("UPDATE process_bpmn SET bpmn_json = ? WHERE process_id = ?", (json.dumps(bpmn_json, ensure_ascii=False), process_id))
    elif not bpmn_row:
        cursor.execute("INSERT INTO process_bpmn (process_id, bpmn_json) VALUES (?, ?)", (process_id, json.dumps(bpmn_json, ensure_ascii=False)))

    seed_risk_scenarios(cursor, process_id, subprocess_ids, asset_ids, case)


def seed_risk_scenarios(cursor, process_id, subprocess_ids, asset_ids, case):
    scenarios = case.get("risk_scenarios")
    if not scenarios:
        scenarios = [
            {
                "subprocess_index": 1,
                "asset_index": 0,
                "risk": case["risk"],
                "probability": case["probability"],
                "vulnerability_level": case.get("vulnerability_level", 2),
                "impact": case["impact"],
                "control_effectiveness": case["control_effectiveness"],
                "cost": case.get("cost", 3),
                "asset_value": case.get("asset_value", 7),
                "recommendation_note": "Риск снижен за счет базовой контрольной меры.",
            }
        ]

    for scenario in scenarios:
        subprocess_id = subprocess_ids[scenario.get("subprocess_index", 1) - 1]
        asset_id = asset_ids[scenario.get("asset_index", 0) % len(asset_ids)]
        threat_id = get_or_create(cursor, "threats", scenario.get("threat", "Сбой процесса"))
        vulnerability_id = get_or_create(
            cursor,
            "vulnerabilities",
            scenario.get("vulnerability", "Недостаточный контроль процесса"),
            ["category"],
            [scenario.get("vulnerability_category", "Process risk")],
        )
        control_id = get_or_create(cursor, "control_measures", scenario.get("control", "Процессная контрольная мера"))

        probability = scenario["probability"]
        vulnerability_level = scenario["vulnerability_level"]
        impact = scenario["impact"]
        control_effectiveness = scenario["control_effectiveness"]
        cost = scenario.get("cost", 3)
        metrics = calculate_process_risk_metrics(
            probability,
            vulnerability_level,
            impact,
            control_effectiveness,
            cost,
            scenario.get("asset_value", case.get("asset_value", 7)),
        )
        risk_category = classify_numeric_risk(metrics["residual_risk"])
        recommendation = scenario.get("recommendation") or recommend_process_risk(
            metrics["residual_risk"],
            control_effectiveness,
            control_id,
            risk_category,
            vulnerability_level,
        )
        if scenario.get("recommendation_note"):
            recommendation = f"{recommendation} {scenario['recommendation_note']}"

        cursor.execute(
            """
            SELECT id FROM process_risks
            WHERE process_id = ? AND subprocess_id = ?
            ORDER BY id
            LIMIT 1
            """,
            (process_id, subprocess_id),
        )
        existing = cursor.fetchone()
        values = (
            process_id,
            subprocess_id,
            asset_id,
            threat_id,
            vulnerability_id,
            control_id,
            scenario["risk"],
            probability,
            vulnerability_level,
            impact,
            metrics["risk_level"],
            control_effectiveness,
            metrics["residual_risk"],
            metrics["risk_level"],
            risk_category,
            cost,
            metrics["risk_reduction"],
            metrics["priority"],
            recommendation,
        )
        if existing:
            cursor.execute(
                """
                UPDATE process_risks
                SET process_id = ?, subprocess_id = ?, asset_id = ?, threat_id = ?, vulnerability_id = ?,
                    control_measure_id = ?, risk_description = ?, probability = ?, vulnerability_level = ?,
                    impact = ?, initial_risk = ?, control_effectiveness = ?, residual_risk = ?,
                    risk_level = ?, risk_category = ?, cost = ?, risk_reduction = ?, priority = ?,
                    ai_recommendation = ?
                WHERE id = ?
                """,
                values + (existing[0],),
            )
            risk_id = existing[0]
        else:
            cursor.execute(
                """
                INSERT INTO process_risks (
                    process_id, subprocess_id, asset_id, threat_id, vulnerability_id, control_measure_id,
                    risk_description, probability, vulnerability_level, impact, initial_risk, control_effectiveness,
                    residual_risk, risk_level, risk_category, cost, risk_reduction, priority, ai_recommendation
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            risk_id = cursor.lastrowid

        cursor.execute(
            """
            UPDATE process_risks
            SET status = ?, risk_owner = ?, mitigation_owner = ?, due_date = ?,
                assessment_source = ?, confidence = ?, evidence = ?, last_reviewed_at = ?
            WHERE id = ?
            """,
            (
                scenario.get("status", "Mitigation planned"),
                scenario.get("risk_owner", case.get("owner")),
                scenario.get("mitigation_owner", scenario.get("risk_owner", case.get("owner"))),
                scenario.get("due_date", "2026-06-30"),
                scenario.get("assessment_source", "Expert"),
                scenario.get("confidence", "Medium"),
                scenario.get("evidence", "Демо-оценка на основе интервью с владельцем процесса и экспертной шкалы 1-3."),
                scenario.get("last_reviewed_at", "2026-05-05"),
                risk_id,
            ),
        )


def seed():
    cases = [
        {
            "process": "Управление инцидентами ИБ",
            "description": "Процесс выявления, классификации, реагирования и отчетности по инцидентам информационной безопасности.",
            "type": "Information Security",
            "owner": "SOC Manager",
            "input": "Логи, события SIEM, обращения пользователей",
            "output": "Классифицированный инцидент, меры реагирования, отчет",
            "regulations": "Политика ИБ, регламент реагирования на инциденты",
            "resources": "SOC, SIEM, аналитики ИБ",
            "assets": [("SIEM", "Сбор и корреляция событий"), ("Сервер логов", "Хранение журналов")],
            "subprocesses": ["Сбор логов", "Анализ событий", "Классификация инцидента", "Реагирование", "Отчетность"],
            "update_bpmn": True,
            "bpmn": {
                "nodes": [
                    {"id": "start", "type": "start", "label": "Поступило событие"},
                    {"id": "collect_logs", "type": "task", "label": "Сбор логов"},
                    {"id": "normalize", "type": "task", "label": "Нормализация и корреляция"},
                    {"id": "triage", "type": "task", "label": "Первичный анализ SOC"},
                    {"id": "critical_gateway", "type": "gateway", "label": "Критичный инцидент?"},
                    {"id": "containment", "type": "task", "label": "Изоляция и сдерживание"},
                    {"id": "deep_analysis", "type": "task", "label": "Глубокий анализ"},
                    {"id": "standard_response", "type": "task", "label": "Стандартное реагирование"},
                    {"id": "recover", "type": "task", "label": "Восстановление сервиса"},
                    {"id": "post_review", "type": "task", "label": "Post-incident review"},
                    {"id": "report", "type": "task", "label": "Формирование отчета"},
                    {"id": "end", "type": "end", "label": "Инцидент закрыт"},
                ],
                "edges": [
                    {"from": "start", "to": "collect_logs"},
                    {"from": "collect_logs", "to": "normalize"},
                    {"from": "normalize", "to": "triage"},
                    {"from": "triage", "to": "critical_gateway"},
                    {"from": "critical_gateway", "to": "containment", "label": "Да"},
                    {"from": "containment", "to": "deep_analysis"},
                    {"from": "deep_analysis", "to": "recover"},
                    {"from": "critical_gateway", "to": "standard_response", "label": "Нет"},
                    {"from": "standard_response", "to": "post_review"},
                    {"from": "recover", "to": "post_review"},
                    {"from": "post_review", "to": "report"},
                    {"from": "report", "to": "end"},
                ],
            },
            "risk": "Задержка классификации инцидента и пропуск критичного события.",
            "probability": 2.7,
            "vulnerability_level": 2.8,
            "impact": 2.8,
            "control_effectiveness": 0.25,
            "cost": 3,
            "asset_value": 8,
            "risk_scenarios": [
                {
                    "subprocess_index": 1,
                    "asset_index": 0,
                    "risk": "Неполный сбор логов приводит к потере событий расследования.",
                    "threat": "Потеря журналов безопасности",
                    "vulnerability": "Источники логов подключены не полностью",
                    "control": "Централизованный сбор логов и контроль полноты источников",
                    "probability": 2.6,
                    "vulnerability_level": 2.4,
                    "impact": 2.7,
                    "control_effectiveness": 0.45,
                    "cost": 3,
                    "asset_value": 8,
                    "status": "Mitigation planned",
                    "risk_owner": "SOC Manager",
                    "mitigation_owner": "SIEM Engineer",
                    "due_date": "2026-05-30",
                    "assessment_source": "Expert",
                    "confidence": "High",
                    "evidence": "Проверка перечня источников SIEM и журнал подключения критичных систем.",
                    "recommendation_note": "После подключения критичных источников и контроля heartbeat остаточный риск снижен.",
                },
                {
                    "subprocess_index": 2,
                    "asset_index": 0,
                    "risk": "Корреляционные правила SIEM не выявляют сложную атаку.",
                    "threat": "Обход правил обнаружения",
                    "vulnerability": "Недостаточно актуальные правила корреляции",
                    "control": "Актуализация правил SIEM и тестирование use-case",
                    "probability": 2.7,
                    "vulnerability_level": 2.8,
                    "impact": 2.9,
                    "control_effectiveness": 0.38,
                    "cost": 4,
                    "asset_value": 9,
                    "status": "In progress",
                    "risk_owner": "SOC Manager",
                    "mitigation_owner": "Detection Engineer",
                    "due_date": "2026-05-20",
                    "assessment_source": "System calculation",
                    "confidence": "High",
                    "evidence": "Результаты тестирования SIEM use-case и список устаревших корреляционных правил.",
                    "recommendation_note": "Рекомендация по обновлению правил уменьшила риск пропуска атаки.",
                },
                {
                    "subprocess_index": 3,
                    "asset_index": 0,
                    "risk": "Инцидент получает неверный приоритет и поздно передается на реагирование.",
                    "threat": "Ошибочная классификация инцидента",
                    "vulnerability": "Нет единой матрицы классификации и SLA",
                    "control": "Матрица критичности инцидентов и SLA эскалации",
                    "probability": 2.4,
                    "vulnerability_level": 2.5,
                    "impact": 2.8,
                    "control_effectiveness": 0.52,
                    "cost": 2,
                    "asset_value": 8,
                    "status": "Approved",
                    "risk_owner": "Incident Manager",
                    "mitigation_owner": "SOC Shift Lead",
                    "due_date": "2026-06-10",
                    "assessment_source": "Expert",
                    "confidence": "Medium",
                    "evidence": "Матрица критичности инцидентов и SLA эскалации согласованы владельцем процесса.",
                    "recommendation_note": "После внедрения матрицы критичности риск снизился до контролируемого уровня.",
                },
                {
                    "subprocess_index": 4,
                    "asset_index": 1,
                    "risk": "Реагирование задерживается из-за неясных ролей и ручной координации.",
                    "threat": "Задержка локализации инцидента",
                    "vulnerability": "Не назначены ответственные за containment",
                    "control": "Runbook реагирования и назначение ответственных",
                    "probability": 2.8,
                    "vulnerability_level": 2.6,
                    "impact": 3.0,
                    "control_effectiveness": 0.5,
                    "cost": 3,
                    "asset_value": 9,
                    "status": "Mitigation planned",
                    "risk_owner": "SOC Manager",
                    "mitigation_owner": "Incident Response Lead",
                    "due_date": "2026-06-15",
                    "assessment_source": "Expert",
                    "confidence": "Medium",
                    "evidence": "Разбор tabletop exercise показал задержки в containment и ручную координацию.",
                    "recommendation_note": "Runbook и ответственные сократили остаточный риск реагирования.",
                },
                {
                    "subprocess_index": 5,
                    "asset_index": 1,
                    "risk": "Отчет не фиксирует причины инцидента и корректирующие действия.",
                    "threat": "Повторение инцидента",
                    "vulnerability": "Нет post-incident review и контроля выполнения action items",
                    "control": "Post-incident review и журнал корректирующих действий",
                    "probability": 2.1,
                    "vulnerability_level": 2.2,
                    "impact": 2.3,
                    "control_effectiveness": 0.6,
                    "cost": 2,
                    "asset_value": 7,
                    "status": "Mitigated",
                    "risk_owner": "SOC Manager",
                    "mitigation_owner": "Compliance Officer",
                    "due_date": "2026-05-25",
                    "assessment_source": "Manual",
                    "confidence": "Medium",
                    "evidence": "Шаблон post-incident review и журнал action items добавлены в процесс отчетности.",
                    "recommendation_note": "Фиксация action items снижает вероятность повторения ошибки.",
                },
            ],
        },
        {
            "process": "Мониторинг SCADA",
            "description": "Процесс мониторинга технологической инфраструктуры и реагирования на отклонения.",
            "type": "Operational Technology",
            "owner": "OT Security Lead",
            "input": "Телеметрия, события SCADA, сетевые логи",
            "output": "Сигналы тревоги, журнал реагирования, отчет по состоянию",
            "regulations": "Политика промышленной безопасности, регламент мониторинга",
            "resources": "SCADA, сеть передачи данных, сервер мониторинга",
            "assets": [("SCADA", "Ключевая система управления"), ("Сервер мониторинга", "Контроль состояния")],
            "subprocesses": ["Сбор телеметрии", "Анализ отклонений", "Эскалация", "Реагирование"],
            "risk": "Недоступность мониторинга SCADA из-за сбоя инфраструктуры.",
            "probability": 2.3,
            "vulnerability_level": 2.4,
            "impact": 3.0,
            "control_effectiveness": 0.35,
            "cost": 5,
            "asset_value": 9,
            "risk_scenarios": [
                {
                    "subprocess_index": 1,
                    "asset_index": 0,
                    "risk": "Потеря телеметрии из-за пробелов в сегментации сети.",
                    "threat": "Потеря видимости телеметрии",
                    "vulnerability": "Неполный мониторинг сегментации сети",
                    "control": "Резервные каналы телеметрии и мониторинг сегментов",
                    "probability": 2.4,
                    "vulnerability_level": 2.3,
                    "impact": 2.9,
                    "control_effectiveness": 0.40,
                    "cost": 4,
                    "asset_value": 9,
                    "status": "Mitigation planned",
                    "risk_owner": "OT Security Lead",
                    "mitigation_owner": "iot.network.engineer",
                    "due_date": "2026-06-20",
                    "assessment_source": "Expert",
                    "confidence": "High",
                    "evidence": "Сетевая карта сегментации и журнал резервных каналов телеметрии.",
                    "recommendation_note": "Резервные каналы снижают риск потери видимости при сбое сегмента.",
                },
                {
                    "subprocess_index": 2,
                    "asset_index": 0,
                    "risk": "Устаревшие пороги анализа не выявляют отклонения на ранней стадии.",
                    "threat": "Необнаруженное отклонение процесса",
                    "vulnerability": "Статичные, устаревшие пороги обнаружения аномалий",
                    "control": "Периодическая перекалибровка порогов и разбор аналитиком",
                    "probability": 2.6,
                    "vulnerability_level": 2.5,
                    "impact": 3.0,
                    "control_effectiveness": 0.30,
                    "cost": 3,
                    "asset_value": 9,
                    "status": "In progress",
                    "risk_owner": "OT Security Lead",
                    "mitigation_owner": "ot.network.engineer",
                    "due_date": "2026-06-05",
                    "assessment_source": "System calculation",
                    "confidence": "Medium",
                    "evidence": "Отчет о пересмотре порогов обнаружения за последний квартал.",
                    "recommendation_note": "Перекалибровка порогов снижает риск пропуска отклонения.",
                },
                {
                    "subprocess_index": 3,
                    "asset_index": 1,
                    "risk": "Усталость от ложных тревог задерживает эскалацию.",
                    "threat": "Задержка эскалации критичного сигнала",
                    "vulnerability": "Высокий уровень ложных срабатываний снижает внимание оператора",
                    "control": "Настройка тревог и многоуровневый runbook эскалации",
                    "probability": 2.3,
                    "vulnerability_level": 2.6,
                    "impact": 2.8,
                    "control_effectiveness": 0.45,
                    "cost": 2,
                    "asset_value": 8,
                    "status": "Mitigated",
                    "risk_owner": "OT Security Lead",
                    "mitigation_owner": "network.security.engineer",
                    "due_date": "2026-05-28",
                    "assessment_source": "Expert",
                    "confidence": "Medium",
                    "evidence": "Настроенные пороги тревог и согласованный runbook эскалации.",
                    "recommendation_note": "Runbook и настройка тревог ускоряют эскалацию критичных событий.",
                },
                {
                    "subprocess_index": 4,
                    "asset_index": 1,
                    "risk": "Ручное переключение на резервный контур управления происходит медленно.",
                    "threat": "Продлённый простой при реагировании на инцидент",
                    "vulnerability": "Процедура failover не автоматизирована",
                    "control": "Автоматизация failover и ежеквартальные учения",
                    "probability": 2.2,
                    "vulnerability_level": 2.4,
                    "impact": 3.0,
                    "control_effectiveness": 0.35,
                    "cost": 5,
                    "asset_value": 9,
                    "status": "Mitigation planned",
                    "risk_owner": "OT Security Lead",
                    "mitigation_owner": "iot.platform.engineer",
                    "due_date": "2026-07-01",
                    "assessment_source": "Expert",
                    "confidence": "Medium",
                    "evidence": "Протокол последних учений failover и план автоматизации.",
                    "recommendation_note": "Автоматизация failover сокращает время простоя при инциденте.",
                },
            ],
        },
        {
            "process": "Обработка персональных данных",
            "description": "Процесс приема, хранения, обработки и передачи персональных данных.",
            "type": "Compliance",
            "owner": "Data Protection Officer",
            "input": "Анкеты, заявки, учетные данные",
            "output": "Обработанные записи, отчеты, уведомления",
            "regulations": "Политика обработки ПДн, требования законодательства",
            "resources": "CRM, база данных, сотрудники поддержки",
            "assets": [("CRM", "Работа с субъектами данных"), ("База персональных данных", "Хранение ПДн")],
            "subprocesses": ["Сбор данных", "Проверка согласий", "Обработка", "Хранение", "Удаление/архивация"],
            "risk": "Утечка данных из-за недостаточного контроля доступа.",
            "probability": 2.5,
            "vulnerability_level": 3.0,
            "impact": 2.9,
            "control_effectiveness": 0.2,
            "cost": 4,
            "asset_value": 8,
            "risk_scenarios": [
                {
                    "subprocess_index": 1,
                    "asset_index": 0,
                    "risk": "Собираются избыточные персональные данные сверх заявленной цели.",
                    "threat": "Нарушение принципа минимизации данных",
                    "vulnerability": "Нет пофайловой валидации против политики сбора данных",
                    "control": "Проверка минимизации данных на уровне схемы при приеме",
                    "probability": 2.3,
                    "vulnerability_level": 2.6,
                    "impact": 2.7,
                    "control_effectiveness": 0.30,
                    "cost": 3,
                    "asset_value": 7,
                    "status": "Mitigation planned",
                    "risk_owner": "Data Protection Officer",
                    "mitigation_owner": "data.quality.engineer",
                    "due_date": "2026-06-12",
                    "assessment_source": "Expert",
                    "confidence": "Medium",
                    "evidence": "Схема формы сбора данных и список полей вне заявленной цели.",
                    "recommendation_note": "Валидация схемы снижает риск избыточного сбора данных.",
                },
                {
                    "subprocess_index": 2,
                    "asset_index": 0,
                    "risk": "Обработка продолжается без действительного или актуального согласия.",
                    "threat": "Неправомерная обработка из-за недействительного согласия",
                    "vulnerability": "Статус согласия не перепроверяется в момент обработки",
                    "control": "Автоматическая проверка статуса согласия перед обработкой",
                    "probability": 2.6,
                    "vulnerability_level": 2.7,
                    "impact": 2.8,
                    "control_effectiveness": 0.25,
                    "cost": 3,
                    "asset_value": 8,
                    "status": "In progress",
                    "risk_owner": "Data Protection Officer",
                    "mitigation_owner": "api.platform.engineer",
                    "due_date": "2026-06-08",
                    "assessment_source": "System calculation",
                    "confidence": "High",
                    "evidence": "Журнал проверок статуса согласия за последний месяц.",
                    "recommendation_note": "Автопроверка согласия снижает риск неправомерной обработки.",
                },
                {
                    "subprocess_index": 3,
                    "asset_index": 1,
                    "risk": "Недостаточный пофайловый контроль доступа при обработке.",
                    "threat": "Несанкционированный внутренний доступ к персональным данным",
                    "vulnerability": "Широкий ролевой доступ без пофайловых ограничений",
                    "control": "Пофайловый контроль доступа и журнал аудита обработки",
                    "probability": 2.5,
                    "vulnerability_level": 2.9,
                    "impact": 2.9,
                    "control_effectiveness": 0.20,
                    "cost": 4,
                    "asset_value": 8,
                    "status": "Mitigation planned",
                    "risk_owner": "Data Protection Officer",
                    "mitigation_owner": "iam.administrator",
                    "due_date": "2026-06-25",
                    "assessment_source": "Expert",
                    "confidence": "Medium",
                    "evidence": "Матрица ролевого доступа и запросы на пофайловые ограничения.",
                    "recommendation_note": "Пофайловый контроль доступа снижает риск внутренней утечки.",
                },
                {
                    "subprocess_index": 4,
                    "asset_index": 1,
                    "risk": "Шифрование данных при хранении не применяется повсеместно.",
                    "threat": "Экспонирование данных через нешифрованное хранилище",
                    "vulnerability": "Устаревшие тома хранения не покрыты политикой шифрования",
                    "control": "Обязательное шифрование при хранении для всех томов",
                    "probability": 2.4,
                    "vulnerability_level": 2.8,
                    "impact": 2.9,
                    "control_effectiveness": 0.30,
                    "cost": 4,
                    "asset_value": 8,
                    "status": "Mitigation planned",
                    "risk_owner": "Data Protection Officer",
                    "mitigation_owner": "platform.security.engineer",
                    "due_date": "2026-07-05",
                    "assessment_source": "Expert",
                    "confidence": "Medium",
                    "evidence": "Инвентаризация томов хранения и статус применения шифрования.",
                    "recommendation_note": "Повсеместное шифрование снижает риск экспонирования данных.",
                },
                {
                    "subprocess_index": 5,
                    "asset_index": 0,
                    "risk": "Срок хранения превышен без удаления или обоснования архивации.",
                    "threat": "Неправомерное удержание персональных данных",
                    "vulnerability": "Нет автоматического контроля срока хранения",
                    "control": "Автоматическое применение политики хранения и журнал удаления",
                    "probability": 2.0,
                    "vulnerability_level": 2.2,
                    "impact": 2.5,
                    "control_effectiveness": 0.55,
                    "cost": 2,
                    "asset_value": 6,
                    "status": "Mitigated",
                    "risk_owner": "Data Protection Officer",
                    "mitigation_owner": "data.quality.engineer",
                    "due_date": "2026-05-15",
                    "assessment_source": "Manual",
                    "confidence": "High",
                    "evidence": "Журнал автоматического удаления записей по истечении срока хранения.",
                    "recommendation_note": "Автоматизация удаления устраняет риск неправомерного удержания данных.",
                },
            ],
        },
    ]

    with get_db_connection() as conn:
        cursor = conn.cursor()
        company_id = get_or_create(cursor, "companies", "Демо организация", ["description", "industry"], ["Демонстрационная компания для процессного анализа рисков", "Education / Critical Infrastructure"])
        for case in cases:
            add_process_case(cursor, company_id, case)
        conn.commit()
    print("Демонстрационные процессные кейсы добавлены.")


if __name__ == "__main__":
    seed()
