# PROJECT_CONTEXT

## Цель
Веб-приложение для оценки рисков активов и процессов через экспертные оценки, процессную модель, BPMN JSON, меры контроля и AI-рекомендации. Проект развивается от asset-risk системы к ProcessRisk AI / RiskFlow AI, с ролями `admin` и `expert`.

## Стек
- Python, Flask
- SQLite: `risk_assessment.db`
- HTML/Jinja templates, Tailwind CSS (через шаблоны)
- NumPy, Matplotlib, Seaborn для расчетов и heatmap
- Werkzeug password hashing, Flask sessions
- Rule-based AI helper: `ai/risk_recommender.py`

## Структура
```text
risk_project/
├── app.py
├── requirements.txt
├── risk_assessment.db
├── add_threats.py
├── populate_vulnerabilities.py
├── populate_control_measures.py
├── seed_process_cases.py
├── ai/
│   └── risk_recommender.py
├── tests/
│   ├── test_risk_calculation.py
│   ├── test_ai_analysis.py
│   └── test_flask_process_flow.py
├── templates/
│   ├── index.html, login.html
│   ├── users.html, experts.html, assets.html
│   ├── asset_evaluations.html, threat_probabilities.html
│   ├── risk_analysis.html, criticality.html
│   ├── companies.html, processes.html, process_detail.html
│   ├── subprocess_form.html, process_bpmn_form.html
│   ├── process_risks.html, process_risk_form.html
│   ├── process_report.html, ai_analysis.html, _bpmn_viewer.html
│   └── add_*/edit_*.html
├── static/
│   └── heatmap_*.png
└── DOCUMENTATION/
    ├── README.md, QUICK_START.md, USER_GUIDE.md
    ├── ARCHITECTURE.md, DEPLOYMENT.md, CHANGELOG.md
    └── ...
```

## Основные файлы
- `app.py`: монолитное Flask-приложение; инициализация БД, расчеты, auth-декораторы, routes.
- `requirements.txt`: зависимости Python.
- `templates/`: Jinja/HTML страницы CRUD, входа, анализа и критичности.
- `static/`: сгенерированные изображения тепловых карт.
- `add_threats.py`, `populate_vulnerabilities.py`, `populate_control_measures.py`: скрипты первичного заполнения справочников.
- `seed_process_cases.py`: создает 3 демо-кейса процессного анализа.
- `seed_complete_case.py`: создает полный end-to-end кейс `Обработка фишингового инцидента` с компанией, активами, подпроцессами, BPMN, рисками, владельцами, сроками, evidence и AI-рекомендациями.
- `ai/risk_recommender.py`: rule-based AI-рекомендации по процессным рискам.
- `DOCUMENTATION/`: подробные руководства; при сомнениях читать точечно.

## Ключевая логика
- `init_db()` создает SQLite-таблицы и default admin `admin`; пароль — из `RISKFLOW_ADMIN_PASSWORD`, либо случайно генерируется и печатается в консоль при первом запуске.
- Сущности: users, experts, assets, asset_evaluations, criteria_weights, threat_probabilities, asset_owners, threats, vulnerabilities, taken_measures, control_measures, risk_analysis.
- Процессные сущности: companies, processes, subprocesses, process_assets, process_bpmn, process_risks.
- Эксперты оценивают активы по 6 критериям: `life_health`, `economy`, `ecology`, `dependency`, `social`, `international`.
- `update_asset_scores(asset_id)` пересчитывает средние оценки актива.
- `update_threat_probability(asset_id)` пересчитывает среднюю вероятность угроз.
- Критичность = сумма оценка * вес; Impact = `1 + (criticality / 10) * 2`.
- `calculate_risk(impact, probability, control_effectiveness)` считает начальный и остаточный риск.
- `/criticality` формирует ранжирование активов по максимальному остаточному риску и heatmap через Seaborn; каждая запись `risk_analysis` считается отдельно.
- `/processes/<id>` показывает карточку процесса: активы, подпроцессы, BPMN JSON, риски и AI-рекомендации.
- `/process_report/<id>` показывает отдельный отчет: описание процесса, BPMN HTML-визуализацию из JSON, активы, подпроцессы, риски, heatmap по процессным рискам, AI-рекомендации и итог.
- `_bpmn_viewer.html` общий SVG BPMN viewer для карточки, отчета и формы редактирования; поддерживает JSON `nodes/edges`, типы `start/task/gateway/end`, координаты `x/y`, labels на связях, стрелки, счетчики узлов/связей и preview.
- BPMN-узлы могут хранить `subprocess_id`; viewer и редактор подсвечивают узлы по max `residual_risk` связанного подпроцесса: green low, yellow medium, red high. Для старых схем есть авто-привязка по похожему названию узла и подпроцесса.
- `build_bpmn_business_context()` строит карту `BPMN node -> subprocess -> assets/threats/vulnerabilities/controls/risks/AI`; карточка процесса, отчет и редактор используют ее для связи диаграммы с бизнес-логикой.
- Демо BPMN для процесса `Управление инцидентами ИБ` содержит сложную ветку: start -> сбор/нормализация/triage -> gateway `Критичный инцидент?` -> критичный путь containment/deep analysis/recover или стандартное реагирование -> post-review -> отчет -> end.
- `/process_risks*` хранит риски на уровне процесса/подпроцесса.
- `process_risks` расширен под метод risk-oriented BPMN: `probability`, `vulnerability_level`, `impact`, числовой `risk_level`, `residual_risk`, `cost`, `risk_reduction`, `priority`, `risk_category`.
- `process_risks` также работает как risk register: `status`, `risk_owner`, `mitigation_owner`, `due_date`, `assessment_source`, `confidence`, `evidence`, `last_reviewed_at`; список `/process_risks` поддерживает фильтры по этим полям.
- Форма `/process_risks/add|edit/<id>` автоматизирует ввод: фильтрует подпроцессы/активы по выбранному процессу, показывает live-расчет potentiality/initial/residual/reduction/category/priority и может автозаполнить owner/status/due date/reviewed date.
- Эксперты участвуют в процессных рисках через `process_risk_expert_assessments`: несколько экспертов оценивают probability/vulnerability/impact/control effectiveness/confidence/evidence, после сохранения средние значения агрегируются обратно в `process_risks`.
- Формулы статьи вынесены в `services/risk_service.py`: `potentiality = probability + vulnerability_level - 1`, `risk_level = potentiality * impact`, `residual_risk = risk_level * (1 - control_effectiveness)`, `risk_reduction = risk_before - risk_after`, `priority = HIGH/MEDIUM/LOW`.
- BPMN API: `GET /api/process_bpmn/<process_id>` загружает BPMN JSON, `POST /api/process_bpmn/<process_id>` сохраняет JSON с `nodes/edges`.
- `/ai_analysis/<id>` показывает отдельный AI-анализ процесса: AI-рейтинг, score 0-9, самый критичный подпроцесс, слабые контроли, риски без контроля, повторяющиеся угрозы/уязвимости, приоритетные действия и текстовый вывод.

## Запуск
```bash
pip install -r requirements.txt
python app.py
```
Открыть: `http://localhost:5000`. Default admin: `admin`, пароль см. в консоли при первом запуске (или задайте `RISKFLOW_ADMIN_PASSWORD`).

Демо-кейсы:
```bash
python seed_process_cases.py
```

## Тесты
Автотесты используют стандартный `unittest` и временную SQLite-БД:
```bash
python -m unittest discover -s tests -v
```
Покрыто: расчет риска, формулы process risk, AI-анализ, BPMN API, login admin, основные страницы процессов, создание компании и процесса через routes.

## Примечания
- Перед изменениями сначала читать этот файл и только затем нужные участки кода/документации.
- Предположение: `risk_assessment.db` является локальной dev-БД, не миграционной схемой для продакшна.
- Полный разбор проекта, схемы, routes, бизнес-логики и рисков сопровождения: `PROJECT_ANALYSIS.md`.
