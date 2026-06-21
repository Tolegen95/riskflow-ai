import json
import re
import sqlite3

from werkzeug.security import generate_password_hash

from services.risk_service import calculate_process_risk_metrics, classify_numeric_risk


DATABASE_PATH = "risk_assessment.db"


def upsert_lookup(cursor, table, name, category=None):
    if table == "vulnerabilities":
        cursor.execute("SELECT id FROM vulnerabilities WHERE name = ?", (name,))
        row = cursor.fetchone()
        if row:
            cursor.execute("UPDATE vulnerabilities SET category = ? WHERE id = ?", (category, row[0]))
            return row[0]
        cursor.execute("INSERT INTO vulnerabilities (name, category) VALUES (?, ?)", (name, category))
        return cursor.lastrowid

    cursor.execute(f"SELECT id FROM {table} WHERE name = ?", (name,))
    row = cursor.fetchone()
    if row:
        return row[0]
    cursor.execute(f"INSERT INTO {table} (name) VALUES (?)", (name,))
    return cursor.lastrowid


def asset_value(cursor, asset_id):
    cursor.execute(
        """
        SELECT life_health, economy, ecology, dependency, social, international
        FROM assets
        WHERE id = ?
        """,
        (asset_id,),
    )
    row = cursor.fetchone()
    values = [value for value in row if value is not None] if row else []
    return sum(values) / len(values) if values else 1


def bpmn(nodes, edges):
    return json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False, indent=2)


def username_from_owner(name):
    aliases = {
        "Traffic Operations Manager": "traffic.owner",
        "Environmental Monitoring Lead": "environment.owner",
        "Smart Lighting Service Owner": "lighting.owner",
        "IoT Security Manager": "iot.security.manager",
    }
    if name in aliases:
        return aliases[name]
    username = re.sub(r"[^a-z0-9]+", ".", name.lower()).strip(".")
    return username[:48] or "user"


def upsert_user(cursor, username, role):
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if row:
        cursor.execute("UPDATE users SET role = ?, expert_id = NULL WHERE id = ?", (role, row[0]))
        return row[0]
    cursor.execute(
        "INSERT INTO users (username, password_hash, role, expert_id) VALUES (?, ?, ?, NULL)",
        (username, generate_password_hash("demo123"), role),
    )
    return cursor.lastrowid


def apply():
    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()

        responsibility_roles = {
            "Traffic Operations Manager": "process_owner",
            "Environmental Monitoring Lead": "process_owner",
            "Smart Lighting Service Owner": "process_owner",
            "IoT Security Manager": "process_owner",
            "Traffic Analytics Lead": "process_owner",
            "OT Network Engineer": "risk_manager",
            "IoT Platform Engineer": "risk_manager",
            "Environmental Data Analyst": "process_owner",
            "Open Data Product Owner": "process_owner",
            "IoT Network Engineer": "risk_manager",
            "Maintenance Dispatcher": "process_owner",
            "Energy Efficiency Analyst": "process_owner",
            "Network Security Engineer": "risk_manager",
            "Firmware Engineer": "risk_manager",
            "IAM Administrator": "risk_manager",
            "Platform Security Engineer": "risk_manager",
            "Data Quality Engineer": "risk_manager",
            "Analytics Engineer": "risk_manager",
            "API Platform Engineer": "risk_manager",
            "Vendor Manager": "risk_manager",
            "Municipal Maintenance Lead": "process_owner",
            "IoT Asset Manager": "risk_manager",
            "NAC Administrator": "risk_manager",
            "Release Manager": "risk_manager",
            "Problem Manager": "risk_manager",
        }
        user_ids = {}
        for owner_name, role in responsibility_roles.items():
            user_ids[owner_name] = upsert_user(cursor, username_from_owner(owner_name), role)

        companies = {
            1: (
                "Astana Smart City Operations Center",
                "Городской центр мониторинга IoT-инфраструктуры: транспорт, освещение, экология, камеры и аварийные события.",
                "Smart city / Urban infrastructure",
            ),
            2: (
                "Urban IoT Platform Provider",
                "Поставщик городской IoT-платформы: edge-шлюзы, MQTT, LoRaWAN/NB-IoT, API и аналитика телеметрии.",
                "IoT platform operations",
            ),
        }
        for company_id, data in companies.items():
            cursor.execute(
                "UPDATE companies SET name = ?, description = ?, industry = ? WHERE id = ?",
                (*data, company_id),
            )

        processes = {
            1: (
                1,
                "Управление дорожным трафиком",
                "Сбор телеметрии с перекрестков, расчет фаз светофоров, передача команд контроллерам и мониторинг аварий.",
                "Smart mobility",
                "Traffic Operations Manager",
                "Данные детекторов транспорта, CCTV analytics, GPS общественного транспорта",
                "Оптимизированные фазы светофоров, аварийные уведомления, журнал команд",
                "Urban traffic policy, ISO 27001, IEC 62443 for OT-like systems",
                "Traffic Controllers, CCTV Analytics, Edge Gateways, Command Center Dashboard",
            ),
            2: (
                1,
                "Мониторинг экологических датчиков",
                "Сбор показаний воздуха, шума и погодных станций, проверка качества данных и публикация городских метрик.",
                "Environmental IoT",
                "Environmental Monitoring Lead",
                "Air quality sensors, noise sensors, weather stations",
                "Индексы качества воздуха, предупреждения, открытые данные",
                "Environmental monitoring policy, data quality procedure",
                "LoRaWAN Gateways, MQTT Broker, Time-Series Database, Citizen Portal",
            ),
            3: (
                1,
                "Управление умным освещением",
                "Дистанционное управление группами светильников, расписания, энергосбережение и обработка отказов.",
                "Smart lighting",
                "Smart Lighting Service Owner",
                "Lighting controller telemetry, schedules, maintenance tickets",
                "Команды диммирования, отчеты энергопотребления, заявки на ремонт",
                "Municipal lighting SLA, IEC 62443, vendor hardening baseline",
                "Lighting Controllers, IoT Device Registry, Maintenance App",
            ),
            4: (
                2,
                "Реагирование на инцидент IoT-устройства",
                "SOC/IoT-команда выявляет подозрительное устройство, изолирует его, проверяет прошивку и восстанавливает сервис.",
                "IoT security operations",
                "IoT Security Manager",
                "Device alerts, gateway logs, firmware inventory, network telemetry",
                "Изолированное устройство, обновленная прошивка, закрытый incident ticket",
                "IoT incident response playbook, ISO 27035, NISTIR 8259 principles",
                "SIEM, IoT Device Registry, Edge Gateway, Firmware Repository, NAC",
            ),
        }
        for process_id, data in processes.items():
            owner_user_id = user_ids.get(data[4])
            cursor.execute(
                """
                UPDATE processes
                SET company_id = ?, name = ?, description = ?, process_type = ?, owner = ?,
                    owner_user_id = ?, input_data = ?, output_data = ?, regulations = ?, resources = ?
                WHERE id = ?
                """,
                (*data[:5], owner_user_id, *data[5:], process_id),
            )

        subprocesses = {
            1: (1, "Сбор телеметрии перекрестков", "Traffic Data Engineer", "Edge Gateway, Traffic Sensors", 1),
            2: (1, "Аналитика дорожной нагрузки", "Traffic Analytics Lead", "CCTV Analytics, Traffic Platform", 2),
            3: (1, "Расчет фаз светофоров", "Traffic Operations Manager", "Traffic Control Platform", 3),
            4: (1, "Передача команд контроллерам", "OT Network Engineer", "Traffic Controllers, OT Network", 4),
            5: (1, "Мониторинг аварий и откатов", "City Dispatch Operator", "Command Center Dashboard, SIEM", 5),
            6: (2, "Сбор показаний датчиков", "IoT Platform Engineer", "LoRaWAN Gateways, MQTT Broker", 1),
            7: (2, "Проверка качества данных", "Environmental Data Analyst", "Stream Processing, Time-Series DB", 2),
            8: (2, "Расчет индексов и тревог", "Environmental Monitoring Lead", "Analytics Engine, Alerting", 3),
            9: (2, "Публикация открытых данных", "Open Data Product Owner", "Citizen Portal, Open API", 4),
            10: (3, "Обновление расписаний освещения", "Lighting Operations Engineer", "Lighting Management Platform", 1),
            11: (3, "Передача команд диммирования", "IoT Network Engineer", "MQTT Broker, Lighting Controllers", 2),
            12: (3, "Контроль отказов светильников", "Maintenance Dispatcher", "Maintenance App, Device Registry", 3),
            13: (3, "Анализ энергопотребления", "Energy Efficiency Analyst", "Time-Series DB, BI Dashboard", 4),
            14: (3, "Планирование обслуживания", "Municipal Maintenance Lead", "Maintenance App, Inventory", 5),
            15: (4, "Выявление аномалии устройства", "SOC Analyst", "SIEM, Device Registry", 1),
            16: (4, "Проверка владельца и локации", "IoT Asset Manager", "Device Registry, GIS", 2),
            17: (4, "Изоляция устройства", "Network Security Engineer", "NAC, Edge Gateway", 3),
            18: (4, "Проверка прошивки и конфигурации", "Firmware Engineer", "Firmware Repository, MDM", 4),
            19: (4, "Восстановление сервиса", "IoT Operations Lead", "Device Registry, Monitoring", 5),
            20: (4, "Post-incident review", "IoT Security Manager", "Service Desk, Knowledge Base", 6),
        }
        for subprocess_id, data in subprocesses.items():
            cursor.execute(
                """
                UPDATE subprocesses
                SET process_id = ?, name = ?, responsible_person = ?, used_systems = ?, order_index = ?
                WHERE id = ?
                """,
                (*data, subprocess_id),
            )

        assets = {
            1: ("Traffic Signal Controllers", 9.0, 8.6, 5.5, 9.2, 8.8, 6.5, 2.6),
            2: ("Roadside Edge Gateways", 7.5, 8.0, 4.5, 8.7, 7.8, 6.0, 2.7),
            3: ("CCTV Analytics Platform", 6.5, 8.2, 3.0, 8.0, 8.0, 6.8, 2.5),
            4: ("Traffic Command Center Dashboard", 7.0, 8.5, 4.0, 8.8, 8.5, 6.5, 2.4),
            5: ("City SIEM Platform", 2.0, 7.8, 1.0, 8.5, 7.0, 6.0, 2.4),
            6: ("LoRaWAN Gateway Network", 3.0, 7.4, 8.0, 8.2, 7.8, 5.5, 2.3),
            7: ("MQTT Broker Cluster", 2.0, 8.0, 6.5, 8.8, 7.5, 5.8, 2.6),
            8: ("Environmental Sensor Fleet", 2.0, 6.8, 9.0, 7.8, 8.2, 5.0, 2.5),
            9: ("Urban Time-Series Database", 2.0, 7.8, 7.5, 8.3, 7.0, 5.5, 2.2),
            10: ("Citizen Open Data Portal", 1.0, 6.8, 6.5, 6.8, 8.0, 6.0, 2.4),
            11: ("Smart Lighting Controllers", 7.0, 7.6, 6.5, 8.4, 8.5, 5.5, 2.5),
            12: ("IoT Device Registry", 2.0, 8.2, 5.5, 8.8, 7.5, 6.0, 2.3),
            13: ("Firmware Repository", 2.0, 7.8, 4.5, 8.0, 7.0, 5.5, 2.4),
            14: ("Municipal Maintenance App", 3.0, 6.8, 5.5, 7.2, 7.8, 4.8, 2.1),
        }
        for asset_id, data in assets.items():
            cursor.execute(
                """
                UPDATE assets
                SET name = ?, life_health = ?, economy = ?, ecology = ?, dependency = ?,
                    social = ?, international = ?, threat_probability = ?
                WHERE id = ?
                """,
                (*data, asset_id),
            )

        experts = {
            1: "Aigerim Sadykova - Smart City Risk Manager",
            2: "Dias Mukhamedzhanov - IoT Platform Architect",
            4: "Sara Tulegenova - City SOC Analyst",
            5: "Askhat Karimov - Urban Infrastructure Auditor",
        }
        for expert_id, name in experts.items():
            cursor.execute("UPDATE experts SET name = ? WHERE id = ?", (name, expert_id))

        cursor.execute("UPDATE asset_owners SET name = ? WHERE id = 1", ("City Digital Operations",))
        cursor.execute("UPDATE asset_owners SET name = ? WHERE id = 2", ("Urban Mobility Department",))
        cursor.execute("UPDATE asset_owners SET name = ? WHERE id = 3", ("Environmental Monitoring Office",))

        cursor.execute("DELETE FROM asset_evaluations")
        cursor.execute("DELETE FROM threat_probabilities")
        for asset_id, values in assets.items():
            _, lh, economy, ecology, dependency, social, international, probability = values
            base_scores = [lh, economy, ecology, dependency, social, international]
            for offset, expert_id in enumerate([1, 2, 4, 5]):
                adjustment = [-0.2, 0.1, 0.2, -0.1][offset]
                scores = [max(0, min(10, round(score + adjustment, 1))) for score in base_scores]
                cursor.execute(
                    """
                    INSERT INTO asset_evaluations
                    (asset_id, expert_id, life_health, economy, ecology, dependency, social, international)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (asset_id, expert_id, *scores),
                )
                cursor.execute(
                    "INSERT INTO threat_probabilities (asset_id, expert_id, probability) VALUES (?, ?, ?)",
                    (asset_id, expert_id, round(max(1, min(3, probability + adjustment / 2)), 1)),
                )

        lookups = {}
        for name in [
            "Компрометация IoT-устройства",
            "Подмена телеметрии датчика",
            "Недоступность edge-шлюза",
            "Несанкционированная команда контроллеру",
            "Массовый отказ городского сервиса",
            "Утечка видеопотока или метаданных",
            "Публикация некорректных открытых данных",
            "Внедрение вредоносной прошивки",
            "Сбой синхронизации времени устройств",
            "DDoS на MQTT/API платформу",
        ]:
            lookups[("threat", name)] = upsert_lookup(cursor, "threats", name)

        vulnerabilities = [
            ("Устройства используют заводские учетные данные", "IoT Identity"),
            ("Нет взаимной TLS-аутентификации MQTT-клиентов", "IoT Network"),
            ("Edge-шлюзы не сегментированы от городской сети", "Network Segmentation"),
            ("Прошивки контроллеров не имеют проверки подписи", "Firmware Security"),
            ("Инвентаризация устройств не синхронизирована с GIS", "Asset Management"),
            ("Неполное покрытие мониторингом edge-шлюзов", "Monitoring"),
            ("Нет контроля целостности телеметрии датчиков", "Data Quality"),
            ("Правила тревог не учитывают дрейф датчиков", "Analytics"),
            ("Открытый API не имеет лимитов и схемы публикации", "API Security"),
            ("Команды диммирования выполняются без подтверждения владельца зоны", "Authorization"),
            ("Нет secure boot на части lighting-контроллеров", "Device Hardening"),
            ("Заявки на обслуживание не связываются с device health", "Operations"),
            ("Репозиторий прошивок не требует двухэтапного утверждения релиза", "Release Management"),
            ("NAC-политики не переводят подозрительные устройства в quarantine VLAN", "Network Access Control"),
            ("Не ведется post-incident review по повторяющимся IoT-аномалиям", "Governance"),
        ]
        for name, category in vulnerabilities:
            lookups[("vulnerability", name)] = upsert_lookup(cursor, "vulnerabilities", name, category)

        controls = [
            "Уникальные сертификаты устройств и ротация ключей",
            "Mutual TLS для MQTT и device API",
            "Сегментация edge-шлюзов и firewall allow-list",
            "Подписанные прошивки и secure boot",
            "Единый device registry с GIS-привязкой",
            "Health monitoring edge-шлюзов с SLA-алертами",
            "Проверка целостности и plausibility checks телеметрии",
            "Калибровка правил тревог по сезонным профилям",
            "API rate limiting и approval workflow открытых данных",
            "RBAC для команд управления зонами освещения",
            "Hardening baseline для lighting-контроллеров",
            "Связь maintenance ticket с device health score",
            "Двухэтапное утверждение firmware release",
            "NAC quarantine VLAN для подозрительных устройств",
            "Post-incident review и trend analysis IoT-аномалий",
        ]
        for name in controls:
            lookups[("control", name)] = upsert_lookup(cursor, "control_measures", name)

        cursor.execute("DELETE FROM process_assets")
        process_assets = [
            (1, 1, "Контроллеры фаз светофоров"),
            (1, 2, "Передача телеметрии и команд на перекрестках"),
            (1, 3, "Видеоаналитика дорожной нагрузки"),
            (1, 4, "Операционная панель диспетчера"),
            (2, 6, "Связь датчиков с платформой"),
            (2, 7, "Прием IoT-сообщений"),
            (2, 8, "Парк экологических датчиков"),
            (2, 9, "Хранение временных рядов"),
            (2, 10, "Публикация городских показателей"),
            (3, 11, "Контроллеры светильников"),
            (3, 12, "Инвентаризация и состояния устройств"),
            (3, 14, "Заявки на ремонт"),
            (4, 5, "Корреляция IoT-аномалий"),
            (4, 12, "Проверка владельца и локации"),
            (4, 13, "Проверка и выпуск прошивок"),
        ]
        for item in process_assets:
            cursor.execute(
                "INSERT OR IGNORE INTO process_assets (process_id, asset_id, role_in_process) VALUES (?, ?, ?)",
                item,
            )

        cursor.execute("DELETE FROM risk_treatment_actions")
        cursor.execute("DELETE FROM process_risk_workflow")
        cursor.execute("DELETE FROM process_risk_expert_assessments")
        cursor.execute("DELETE FROM process_risks")
        risks = [
            (1, 1, 2, "Недоступность edge-шлюза", "Неполное покрытие мониторингом edge-шлюзов", "Health monitoring edge-шлюзов с SLA-алертами", "Отказ edge-шлюза на перекрестке остается незамеченным, телеметрия и команды управления задерживаются.", 2.6, 2.3, 3.0, 0.42, 3.0, "In progress", "Traffic Operations Manager", "IoT Platform Engineer", "2026-06-04", "Monitoring", "High", "12% gateways have no heartbeat alert"),
            (1, 2, 3, "Утечка видеопотока или метаданных", "Edge-шлюзы не сегментированы от городской сети", "Сегментация edge-шлюзов и firewall allow-list", "Видеоаналитика доступна из общей городской сети, повышается риск lateral movement и утечки метаданных.", 2.3, 2.4, 2.8, 0.45, 4.0, "Mitigation planned", "Traffic Analytics Lead", "Network Security Engineer", "2026-06-15", "Audit", "High", "Flat network segment found at 18 intersections"),
            (1, 3, 1, "Несанкционированная команда контроллеру", "Команды диммирования выполняются без подтверждения владельца зоны", "RBAC для команд управления зонами освещения", "Оператор с избыточными правами может изменить режим работы контроллеров трафика без второго подтверждения.", 2.0, 2.3, 3.0, 0.38, 4.5, "Approved", "Traffic Operations Manager", "IAM Administrator", "2026-05-30", "Access review", "High", "Shared operator role used by 9 dispatchers"),
            (1, 4, 1, "Массовый отказ городского сервиса", "Прошивки контроллеров не имеют проверки подписи", "Подписанные прошивки и secure boot", "Непроверенная прошивка контроллера может привести к некорректным фазам светофоров.", 2.1, 2.6, 3.0, 0.30, 6.0, "Mitigation planned", "OT Network Engineer", "Firmware Engineer", "2026-06-22", "Vendor assessment", "High", "34% traffic controllers lack signed firmware validation"),
            (2, 6, 6, "Недоступность edge-шлюза", "Нет взаимной TLS-аутентификации MQTT-клиентов", "Mutual TLS для MQTT и device API", "Фальшивый клиент может подключиться к брокеру и создавать шум в потоке телеметрии.", 2.5, 2.4, 2.7, 0.44, 3.5, "In progress", "IoT Platform Engineer", "Platform Security Engineer", "2026-06-07", "Architecture review", "High", "Legacy gateway profile still accepts token-only auth"),
            (2, 7, 8, "Подмена телеметрии датчика", "Нет контроля целостности телеметрии датчиков", "Проверка целостности и plausibility checks телеметрии", "Некорректные данные о качестве воздуха могут попасть в отчетность и публичный портал.", 2.7, 2.5, 2.9, 0.36, 4.0, "Approved", "Environmental Monitoring Lead", "Data Quality Engineer", "2026-06-12", "Data quality review", "High", "Outlier checks disabled for 3 sensor types"),
            (2, 8, 9, "Публикация некорректных открытых данных", "Правила тревог не учитывают дрейф датчиков", "Калибровка правил тревог по сезонным профилям", "Алгоритм может создать ложную тревогу о загрязнении или пропустить реальное превышение.", 2.4, 2.2, 2.6, 0.48, 2.5, "In review", "Environmental Data Analyst", "Analytics Engineer", "2026-05-29", "Expert", "Medium", "Sensor drift was found in winter calibration dataset"),
            (2, 9, 10, "DDoS на MQTT/API платформу", "Открытый API не имеет лимитов и схемы публикации", "API rate limiting и approval workflow открытых данных", "Open API может быть перегружен запросами, городской портал станет недоступен.", 2.2, 2.1, 2.4, 0.55, 2.0, "Mitigated", "Open Data Product Owner", "API Platform Engineer", "2026-05-24", "Load test", "Medium", "Rate limiting enabled for top endpoints"),
            (3, 10, 11, "Несанкционированная команда контроллеру", "Команды диммирования выполняются без подтверждения владельца зоны", "RBAC для команд управления зонами освещения", "Ошибочная или несанкционированная команда может отключить освещение в критичной зоне.", 2.5, 2.3, 2.8, 0.40, 3.5, "In progress", "Smart Lighting Service Owner", "IAM Administrator", "2026-06-03", "Access review", "High", "Zone admin rights granted to vendor support account"),
            (3, 11, 11, "Компрометация IoT-устройства", "Нет secure boot на части lighting-контроллеров", "Hardening baseline для lighting-контроллеров", "Компрометированный контроллер может использоваться как точка входа в IoT-сеть.", 2.6, 2.5, 2.7, 0.35, 4.0, "Mitigation planned", "IoT Network Engineer", "Vendor Manager", "2026-06-18", "Device audit", "High", "Legacy lighting firmware lacks secure boot"),
            (3, 12, 12, "Массовый отказ городского сервиса", "Заявки на обслуживание не связываются с device health", "Связь maintenance ticket с device health score", "Отказы светильников накапливаются без приоритизации по критичным улицам и социальным объектам.", 2.1, 2.0, 2.5, 0.52, 2.0, "Mitigation planned", "Maintenance Dispatcher", "Municipal Maintenance Lead", "2026-06-25", "Operations review", "Medium", "Maintenance backlog not linked with device health"),
            (3, 13, 9, "Подмена телеметрии датчика", "Нет контроля целостности телеметрии датчиков", "Проверка целостности и plausibility checks телеметрии", "Некорректные данные энергопотребления искажают расчет экономии и бюджет обслуживания.", 2.0, 2.0, 2.4, 0.50, 2.0, "Accepted", "Energy Efficiency Analyst", "Data Quality Engineer", "2026-07-01", "Management decision", "Medium", "Risk accepted until platform upgrade Q3"),
            (4, 15, 5, "Компрометация IoT-устройства", "Инвентаризация устройств не синхронизирована с GIS", "Единый device registry с GIS-привязкой", "SOC видит аномалию устройства, но не может быстро определить владельца, локацию и критичность.", 2.6, 2.4, 2.9, 0.45, 3.5, "In progress", "IoT Security Manager", "IoT Asset Manager", "2026-06-06", "Incident review", "High", "21 devices missing GIS location"),
            (4, 17, 2, "Компрометация IoT-устройства", "NAC-политики не переводят подозрительные устройства в quarantine VLAN", "NAC quarantine VLAN для подозрительных устройств", "Подозрительное устройство остается в production-сегменте после срабатывания SIEM.", 2.7, 2.6, 3.0, 0.38, 4.5, "Approved", "Network Security Engineer", "NAC Administrator", "2026-06-14", "Tabletop exercise", "High", "Quarantine action is manual for roadside gateways"),
            (4, 18, 13, "Внедрение вредоносной прошивки", "Репозиторий прошивок не требует двухэтапного утверждения релиза", "Двухэтапное утверждение firmware release", "Ошибочный или вредоносный firmware package может попасть в rollout без независимой проверки.", 2.2, 2.4, 3.0, 0.42, 3.0, "Mitigation planned", "Firmware Engineer", "Release Manager", "2026-06-20", "Release audit", "High", "Firmware repository has single-approver workflow"),
            (4, 20, 12, "Массовый отказ городского сервиса", "Не ведется post-incident review по повторяющимся IoT-аномалиям", "Post-incident review и trend analysis IoT-аномалий", "Повторяющиеся аномалии устройств закрываются как одиночные тикеты, системная причина не устраняется.", 2.0, 2.1, 2.4, 0.58, 1.5, "Mitigated", "IoT Security Manager", "Problem Manager", "2026-05-27", "SOC metrics", "Medium", "PIR template deployed for IoT incidents"),
        ]
        for risk in risks:
            (
                process_id, subprocess_id, asset_id, threat_name, vulnerability_name, control_name,
                description, probability, vulnerability_level, impact, control_effectiveness, cost,
                status, risk_owner, mitigation_owner, due_date, source, confidence, evidence,
            ) = risk
            metrics = calculate_process_risk_metrics(
                probability, vulnerability_level, impact, control_effectiveness, cost, asset_value(cursor, asset_id)
            )
            risk_category = classify_numeric_risk(metrics["residual_risk"])
            cursor.execute(
                """
                INSERT INTO process_risks (
                    process_id, subprocess_id, asset_id, threat_id, vulnerability_id, control_measure_id,
                    risk_description, probability, vulnerability_level, impact, initial_risk,
                    control_effectiveness, residual_risk, risk_level, risk_category, cost,
                    risk_reduction, priority, ai_recommendation, status, risk_owner,
                    mitigation_owner, risk_owner_user_id, mitigation_owner_user_id, due_date,
                    assessment_source, confidence, evidence, last_reviewed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE('now'))
                """,
                (
                    process_id, subprocess_id, asset_id, lookups[("threat", threat_name)],
                    lookups[("vulnerability", vulnerability_name)], lookups[("control", control_name)],
                    description, probability, vulnerability_level, impact, metrics["risk_level"],
                    control_effectiveness, metrics["residual_risk"], metrics["risk_level"], risk_category,
                    cost, metrics["risk_reduction"], metrics["priority"],
                    f"Приоритет: {metrics['priority']}. Внедрить контроль: {control_name}. Проверить эффективность на следующем цикле мониторинга.",
                    status, risk_owner, mitigation_owner, user_ids.get(risk_owner), user_ids.get(mitigation_owner),
                    due_date, source, confidence, evidence,
                ),
            )

        cursor.execute("DELETE FROM process_risk_expert_assessments")
        cursor.execute(
            """
            SELECT id, asset_id, cost, probability, vulnerability_level, impact, control_effectiveness,
                   risk_category, priority
            FROM process_risks
            ORDER BY id
            """
        )
        seeded_risks = cursor.fetchall()
        expert_profiles = [
            (1, -0.1, 0.0, 0.1, 0.02, "High", "Smart City risk manager review: business impact and SLA checked."),
            (2, 0.1, 0.1, 0.0, -0.03, "Medium", "IoT architect review: platform exposure and technical controls checked."),
            (4, 0.0, 0.2, 0.1, -0.02, "High", "City SOC review: monitoring evidence and recent alerts checked."),
            (5, -0.2, -0.1, 0.0, 0.04, "Medium", "Infrastructure audit review: compensating controls and documentation checked."),
        ]
        for risk_id, asset_id, cost, probability, vulnerability_level, impact, control_effectiveness, _, _ in seeded_risks:
            for expert_id, p_adj, v_adj, i_adj, eff_adj, confidence, evidence in expert_profiles:
                cursor.execute(
                    """
                    INSERT INTO process_risk_expert_assessments (
                        process_risk_id, expert_id, probability, vulnerability_level, impact,
                        control_effectiveness, confidence, evidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        risk_id,
                        expert_id,
                        round(max(1, min(3, probability + p_adj)), 1),
                        round(max(1, min(3, vulnerability_level + v_adj)), 1),
                        round(max(1, min(3, impact + i_adj)), 1),
                        round(max(0, min(1, control_effectiveness + eff_adj)), 2),
                        confidence,
                        evidence,
                    ),
                )

            cursor.execute(
                """
                SELECT AVG(probability), AVG(vulnerability_level), AVG(impact), AVG(control_effectiveness)
                FROM process_risk_expert_assessments
                WHERE process_risk_id = ?
                """,
                (risk_id,),
            )
            avg_probability, avg_vulnerability, avg_impact, avg_effectiveness = cursor.fetchone()
            metrics = calculate_process_risk_metrics(
                avg_probability,
                avg_vulnerability,
                avg_impact,
                avg_effectiveness,
                cost,
                asset_value(cursor, asset_id),
            )
            risk_category = classify_numeric_risk(metrics["residual_risk"])
            cursor.execute(
                """
                UPDATE process_risks
                SET probability = ?, vulnerability_level = ?, impact = ?, control_effectiveness = ?,
                    initial_risk = ?, residual_risk = ?, risk_level = ?, risk_category = ?,
                    risk_reduction = ?, priority = ?, assessment_source = 'Expert aggregate',
                    confidence = 'High', last_reviewed_at = DATE('now')
                WHERE id = ?
                """,
                (
                    avg_probability,
                    avg_vulnerability,
                    avg_impact,
                    avg_effectiveness,
                    metrics["risk_level"],
                    metrics["residual_risk"],
                    metrics["risk_level"],
                    risk_category,
                    metrics["risk_reduction"],
                    metrics["priority"],
                    risk_id,
                ),
            )

        cursor.execute(
            """
            SELECT pr.id, pr.risk_description, pr.residual_risk, pr.risk_category, pr.status,
                   pr.mitigation_owner, pr.due_date, pr.cost, cm.name
            FROM process_risks pr
            LEFT JOIN control_measures cm ON cm.id = pr.control_measure_id
            ORDER BY pr.residual_risk DESC
            """
        )
        for risk_id, description, residual, category, risk_status, owner, due_date, cost, control_name in cursor.fetchall():
            if risk_status in ("Mitigated", "Accepted"):
                treatment_status = "Completed" if risk_status == "Mitigated" else "Accepted"
                progress = 100
                actual_residual = round((residual or 0) * 0.9, 2)
            elif risk_status in ("Approved", "In progress"):
                treatment_status = "In progress"
                progress = 45 if risk_status == "Approved" else 65
                actual_residual = None
            elif risk_status == "In review":
                treatment_status = "Waiting validation"
                progress = 30
                actual_residual = None
            else:
                treatment_status = "Planned"
                progress = 10
                actual_residual = None

            expected_residual = round(max(0, (residual or 0) * (0.55 if category == "Высокий" else 0.65)), 2)
            title = control_name or "Усилить контроль обработки риска"
            cursor.execute(
                """
                INSERT INTO risk_treatment_actions (
                    process_risk_id, title, description, treatment_type, owner, due_date, cost,
                    expected_residual_risk, actual_residual_risk, progress, status, evidence, owner_user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    risk_id,
                    title,
                    f"Внедрить и подтвердить эффективность меры для риска: {description}",
                    "Mitigate" if risk_status != "Accepted" else "Accept",
                    owner,
                    due_date,
                    cost,
                    expected_residual,
                    actual_residual,
                    progress,
                    treatment_status,
                    "План создан на основе Smart City / IoT risk register и текущего статуса риска.",
                    user_ids.get(owner),
                ),
            )

        cursor.execute("DELETE FROM risk_analysis")
        for asset_id, owner_id, threat_name, vulnerability_name, control_name, effectiveness in [
            (1, 2, "Несанкционированная команда контроллеру", "Прошивки контроллеров не имеют проверки подписи", "Подписанные прошивки и secure boot", 0.30),
            (8, 3, "Подмена телеметрии датчика", "Нет контроля целостности телеметрии датчиков", "Проверка целостности и plausibility checks телеметрии", 0.36),
            (11, 1, "Компрометация IoT-устройства", "Нет secure boot на части lighting-контроллеров", "Hardening baseline для lighting-контроллеров", 0.35),
        ]:
            cursor.execute(
                """
                INSERT INTO risk_analysis
                (asset_id, asset_owner_id, threat_id, vulnerability_id, taken_measure_id, control_measure_id, control_effectiveness)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    asset_id, owner_id, lookups[("threat", threat_name)],
                    lookups[("vulnerability", vulnerability_name)], lookups[("control", control_name)], effectiveness,
                ),
            )

        latest_bpmn = {
            1: bpmn(
                [
                    {"id": "start", "type": "start", "label": "Телеметрия поступила", "x": 70, "y": 210},
                    {"id": "collect", "type": "task", "label": "Сбор телеметрии", "x": 250, "y": 130, "subprocess_id": 1},
                    {"id": "analytics", "type": "task", "label": "Аналитика нагрузки", "x": 450, "y": 210, "subprocess_id": 2},
                    {"id": "phase", "type": "task", "label": "Расчет фаз", "x": 650, "y": 130, "subprocess_id": 3},
                    {"id": "command", "type": "task", "label": "Команды контроллерам", "x": 850, "y": 210, "subprocess_id": 4},
                    {"id": "monitor", "type": "task", "label": "Мониторинг аварий", "x": 1050, "y": 130, "subprocess_id": 5},
                    {"id": "end", "type": "end", "label": "Трафик управляется", "x": 1250, "y": 210},
                ],
                [
                    {"from": "start", "to": "collect"}, {"from": "collect", "to": "analytics"},
                    {"from": "analytics", "to": "phase"}, {"from": "phase", "to": "command"},
                    {"from": "command", "to": "monitor"}, {"from": "monitor", "to": "end"},
                ],
            ),
            2: bpmn(
                [
                    {"id": "start", "type": "start", "label": "Датчики активны", "x": 70, "y": 210},
                    {"id": "collect", "type": "task", "label": "Сбор показаний", "x": 250, "y": 130, "subprocess_id": 6},
                    {"id": "quality", "type": "task", "label": "Качество данных", "x": 450, "y": 210, "subprocess_id": 7},
                    {"id": "alerts", "type": "task", "label": "Индексы и тревоги", "x": 650, "y": 130, "subprocess_id": 8},
                    {"id": "publish", "type": "task", "label": "Открытые данные", "x": 850, "y": 210, "subprocess_id": 9},
                    {"id": "end", "type": "end", "label": "Метрики опубликованы", "x": 1050, "y": 130},
                ],
                [
                    {"from": "start", "to": "collect"}, {"from": "collect", "to": "quality"},
                    {"from": "quality", "to": "alerts"}, {"from": "alerts", "to": "publish"},
                    {"from": "publish", "to": "end"},
                ],
            ),
            3: bpmn(
                [
                    {"id": "start", "type": "start", "label": "Расписание готово", "x": 70, "y": 210},
                    {"id": "schedule", "type": "task", "label": "Обновление расписаний", "x": 250, "y": 130, "subprocess_id": 10},
                    {"id": "dim", "type": "task", "label": "Команды диммирования", "x": 450, "y": 210, "subprocess_id": 11},
                    {"id": "failures", "type": "task", "label": "Контроль отказов", "x": 650, "y": 130, "subprocess_id": 12},
                    {"id": "energy", "type": "task", "label": "Энергопотребление", "x": 850, "y": 210, "subprocess_id": 13},
                    {"id": "maintenance", "type": "task", "label": "Обслуживание", "x": 1050, "y": 130, "subprocess_id": 14},
                    {"id": "end", "type": "end", "label": "Сервис стабилен", "x": 1250, "y": 210},
                ],
                [
                    {"from": "start", "to": "schedule"}, {"from": "schedule", "to": "dim"},
                    {"from": "dim", "to": "failures"}, {"from": "failures", "to": "energy"},
                    {"from": "energy", "to": "maintenance"}, {"from": "maintenance", "to": "end"},
                ],
            ),
            4: bpmn(
                [
                    {"id": "start", "type": "start", "label": "Аномалия IoT", "x": 70, "y": 220},
                    {"id": "detect", "type": "task", "label": "Выявление аномалии", "x": 260, "y": 130, "subprocess_id": 15},
                    {"id": "owner", "type": "task", "label": "Владелец и локация", "x": 460, "y": 220, "subprocess_id": 16},
                    {"id": "isolate", "type": "task", "label": "Изоляция устройства", "x": 660, "y": 130, "subprocess_id": 17},
                    {"id": "firmware", "type": "task", "label": "Проверка прошивки", "x": 860, "y": 220, "subprocess_id": 18},
                    {"id": "restore", "type": "task", "label": "Восстановление", "x": 1060, "y": 130, "subprocess_id": 19},
                    {"id": "review", "type": "task", "label": "Post-incident review", "x": 1260, "y": 220, "subprocess_id": 20},
                    {"id": "end", "type": "end", "label": "Инцидент закрыт", "x": 1460, "y": 130},
                ],
                [
                    {"from": "start", "to": "detect"}, {"from": "detect", "to": "owner"},
                    {"from": "owner", "to": "isolate"}, {"from": "isolate", "to": "firmware"},
                    {"from": "firmware", "to": "restore"}, {"from": "restore", "to": "review"},
                    {"from": "review", "to": "end"},
                ],
            ),
        }
        for process_id, model in latest_bpmn.items():
            cursor.execute(
                "INSERT INTO process_bpmn (process_id, bpmn_json, bpmn_xml) VALUES (?, ?, '')",
                (process_id, model),
            )

        conn.commit()


if __name__ == "__main__":
    apply()
    print("Smart City / IoT demo data applied.")
