# Полный анализ проекта

## 1. Назначение

Проект `risk_project` - веб-система оценки рисков активов. Она собирает экспертные оценки активов, усредняет показатели, рассчитывает критичность, impact, первоначальный и остаточный риск, а затем показывает ранжирование и тепловую карту.

Основной сценарий:

1. Администратор создает экспертов, пользователей и активы.
2. Эксперты оценивают активы по 6 критериям и задают вероятность угрозы.
3. Администратор ведет таблицу анализа рисков: владелец актива, угроза, уязвимость, принятая мера, контроль и эффективность контроля.
4. Система рассчитывает риски и отображает итоговую таблицу `/criticality`.

## 2. Технологический стек

- Python 3.7+ по документации.
- Flask - HTTP routes, templates, sessions, flash-сообщения.
- SQLite - локальная БД `risk_assessment.db`.
- Jinja2 templates - HTML-страницы в `templates/`.
- Tailwind CSS 2.2.19 через CDN в `templates/index.html`.
- NumPy - подготовка матрицы данных для heatmap.
- Matplotlib + Seaborn - генерация PNG тепловых карт в `static/`.
- Werkzeug security - `generate_password_hash`, `check_password_hash`.

Зависимости в `requirements.txt`:

```text
Flask>=2.0.0
matplotlib>=3.4.0
seaborn>=0.11.0
numpy>=1.21.0
```

## 3. Архитектура

Архитектура фактически монолитная:

- `app.py` содержит все: конфигурацию Flask, схему БД, seed-данные, auth, бизнес-логику, CRUD routes и генерацию графиков.
- Модельного слоя/ORM нет; SQL написан напрямую через `sqlite3`.
- Отдельных service/controller модулей нет.
- HTML вынесен в `templates/`, но большая часть структуры UI повторяется между страницами.
- `static/` хранит сгенерированные PNG heatmap.
- Справочники наполняются отдельными скриптами.

Паттерн ближе к простому MVC:

- Model: SQLite tables + SQL-запросы в `app.py`.
- View: Jinja templates.
- Controller: Flask route functions в `app.py`.

## 4. Структура файлов

```text
risk_project/
├── app.py
├── requirements.txt
├── risk_assessment.db
├── add_threats.py
├── populate_vulnerabilities.py
├── populate_control_measures.py
├── README.md
├── GITHUB_SETUP.md
├── PROJECT_CONTEXT.md
├── AI_RULES.md
├── PROJECT_ANALYSIS.md
├── templates/
│   ├── index.html
│   ├── login.html
│   ├── users.html
│   ├── add_user.html
│   ├── experts.html
│   ├── add_expert.html
│   ├── edit_expert.html
│   ├── assets.html
│   ├── add_asset.html
│   ├── edit_asset.html
│   ├── asset_evaluations.html
│   ├── add_asset_evaluation.html
│   ├── edit_asset_evaluation.html
│   ├── threat_probabilities.html
│   ├── add_threat_probability.html
│   ├── edit_threat_probability.html
│   ├── risk_analysis.html
│   ├── add_risk_analysis.html
│   ├── edit_risk_analysis.html
│   └── criticality.html
├── static/
│   └── heatmap_*.png
└── DOCUMENTATION/
    ├── README.md
    ├── QUICK_START.md
    ├── USER_GUIDE.md
    ├── ARCHITECTURE.md
    ├── DEPLOYMENT.md
    └── CHANGELOG.md
```

## 5. Основные модули

### `app.py`

Главный файл, 1128 строк. Содержит:

- настройку `matplotlib.use('Agg')` для серверной генерации PNG;
- создание `Flask(__name__)`;
- фиксированный `app.secret_key = 'supersecretkey'`;
- `init_db()` и автоматический вызов при импорте;
- функции пересчета оценок и риска;
- auth decorators;
- все routes приложения;
- запуск `app.run(debug=True)`.

### `add_threats.py`

Заполняет таблицу `threats`. Содержит 49 угроз: пожар, затопление, сбои инфраструктуры, кража, вредоносное ПО, DoS, социальная инженерия и т.д. Скрипт проверяет наличие таблицы, вставляет записи, пропускает дубликаты по UNIQUE.

### `populate_vulnerabilities.py`

Заполняет таблицу `vulnerabilities`. Содержит 123 уязвимости по категориям:

- Information
- Systems
- Equipment
- Rooms
- Personnel
- Service

Вставка также идемпотентная через обработку `sqlite3.IntegrityError`.

### `populate_control_measures.py`

Заполняет таблицу `control_measures`. Содержит 114 ISO/IEC 27001-style контролей, в основном разделы A.5-A.18. В `init_db()` есть только первые 6 контролей, полный набор добавляется этим скриптом.

### `templates/`

Jinja templates для CRUD и отчетов. Большинство страниц наследуются от `index.html`.

`index.html` выполняет роль layout:

- подключает Tailwind CDN;
- показывает навигацию;
- скрывает пункты меню по роли;
- выводит flash-сообщения;
- содержит `{% block content %}`.

`login.html` самостоятельный шаблон входа, без наследования layout.

## 6. База данных

Файл БД: `risk_assessment.db`.

Текущие таблицы:

- `users`
- `experts`
- `assets`
- `asset_evaluations`
- `criteria_weights`
- `threat_probabilities`
- `asset_owners`
- `threats`
- `vulnerabilities`
- `taken_measures`
- `control_measures`
- `risk_analysis`

Текущие счетчики записей в локальной БД:

```text
users: 3
experts: 2
assets: 4
asset_evaluations: 6
threat_probabilities: 6
asset_owners: 3
threats: 49
vulnerabilities: 123
taken_measures: 4
control_measures: 114
risk_analysis: 2
```

Текущие пользователи без password hash:

```text
admin: role=admin
Tolegen: role=expert, expert_id=1
Gul: role=expert, expert_id=2
```

Текущие эксперты:

```text
1: Tolegen Aidynov
2: Gulsipat Abisheva
```

Текущие активы:

```text
SCADA-системы
Система "Перевозки"
Система продажи билетов
test active 1
```

## 7. Схема данных

### `users`

- `id`
- `username` UNIQUE
- `password_hash`
- `role` CHECK `admin` или `expert`
- `expert_id` nullable FK на `experts.id`

Администратор обычно без `expert_id`. Экспертный пользователь должен быть связан с записью в `experts`.

### `experts`

- `id`
- `name` UNIQUE

Справочник экспертов, от имени которых создаются оценки.

### `assets`

- `id`
- `name` UNIQUE
- `life_health`
- `economy`
- `ecology`
- `dependency`
- `social`
- `international`
- `threat_probability`

Хранит агрегированные средние оценки по активу и среднюю вероятность угрозы.

### `asset_evaluations`

- `id`
- `asset_id` FK
- `expert_id` FK
- 6 оценочных критериев от 0 до 10

Одна экспертная оценка конкретного актива. Уникальность пары `(asset_id, expert_id)` проверяется кодом, но не закреплена UNIQUE constraint в БД.

### `criteria_weights`

- веса 6 критериев.

По умолчанию:

```text
life_health: 0.419
economy: 0.252
ecology: 0.099
dependency: 0.144
social: 0.051
international: 0.035
```

### `threat_probabilities`

- `id`
- `asset_id` FK
- `expert_id` FK
- `probability` от 1 до 3

Одна экспертная оценка вероятности угрозы для актива. Уникальность пары `(asset_id, expert_id)` проверяется кодом.

### `asset_owners`

Справочник владельцев активов. Seed в `init_db()`:

- IT Department
- Operations
- Finance

### `threats`

Справочник угроз. Полный набор добавляется `add_threats.py`.

### `vulnerabilities`

Справочник уязвимостей с категориями. Полный набор добавляется `populate_vulnerabilities.py`.

### `taken_measures`

Seed в `init_db()`:

- Минимизация рисков и выбор контролей
- Передача рисков третьей стороне (страхование)
- Отказ от риска
- Принятие риска

### `control_measures`

Справочник контролей. `init_db()` добавляет 6 начальных ISO-контролей, `populate_control_measures.py` добавляет полный набор.

### `risk_analysis`

- `asset_id`
- `asset_owner_id`
- `threat_id`
- `vulnerability_id`
- `taken_measure_id`
- `control_measure_id`
- `control_effectiveness`

Связывает актив с владельцем, угрозой, уязвимостью и выбранной реакцией на риск.

## 8. Роли и доступ

### `login_required`

Проверяет наличие `user_id` в Flask session.

### `admin_required`

Требует входа и `session['role'] == 'admin'`.

Доступ администратора:

- пользователи;
- эксперты;
- создание/редактирование/удаление активов;
- все оценки;
- все вероятности;
- CRUD анализа рисков;
- критичность и риски.

### `expert_required`

Разрешает роли `admin` и `expert`.

Эксперт:

- видит список активов;
- видит и редактирует только свои оценки;
- видит и редактирует только свои вероятности угроз;
- видит страницу критичности и рисков.

## 9. HTTP routes

### Auth и главная

- `GET /` - если не вошел, редирект на `/login`; иначе layout/main page.
- `GET|POST /login` - вход по username/password.
- `GET /logout` - очистка session.

### Пользователи, только admin

- `GET /users` - список пользователей.
- `GET|POST /users/add` - создание пользователя; для role `expert` обязателен `expert_id`.

Удаления/редактирования пользователей нет.

### Эксперты, только admin

- `GET /experts`
- `GET|POST /experts/add`
- `GET|POST /experts/edit/<id>`
- `POST /experts/delete/<id>`

Удаление запрещается, если у эксперта есть оценки активов или вероятности угроз.

### Активы

- `GET /assets` - доступ всем авторизованным.
- `GET|POST /assets/add` - только admin.
- `GET|POST /assets/edit/<id>` - только admin.
- `POST /assets/delete/<id>` - только admin.

Удаление актива запрещается, если есть оценки, вероятности угроз или записи анализа рисков.

### Оценки активов

- `GET /asset_evaluations` - admin видит все, expert только свои.
- `GET|POST /asset_evaluations/add` - admin выбирает эксперта, expert создает от своего имени.
- `GET|POST /asset_evaluations/edit/<id>` - expert может редактировать только свое.
- `POST /asset_evaluations/delete/<id>` - expert может удалить только свое.

Валидация: все 6 критериев должны быть в диапазоне 0-10.

### Вероятности угроз

- `GET /threat_probabilities` - admin видит все, expert только свои.
- `GET|POST /threat_probabilities/add`
- `GET|POST /threat_probabilities/edit/<id>`
- `POST /threat_probabilities/delete/<id>`

Валидация: вероятность от 1 до 3.

### Анализ рисков, только admin

- `GET /risk_analysis`
- `GET|POST /risk_analysis/add`
- `GET|POST /risk_analysis/edit/<id>`
- `POST /risk_analysis/delete/<id>`
- `POST /update_risk_analysis/<asset_id>` - JSON endpoint для массового обновления записей `risk_analysis` по `asset_id`.

Если выбранная принятая мера не равна `Минимизация рисков и выбор контролей`, `control_measure_id` сбрасывается в `None`.

### Отчет

- `GET /criticality` - доступ всем авторизованным.

Строит:

- таблицу весов критериев;
- ранжирование активов;
- heatmap;
- Risk analysis table.

## 10. Расчетная бизнес-логика

### Средние оценки актива

После добавления/редактирования/удаления `asset_evaluations` вызывается:

```text
update_asset_scores(asset_id)
```

Она считает AVG по каждому из 6 критериев и записывает результат в `assets`.

Важная особенность: если после удаления оценок у актива больше не осталось оценок, функция не сбрасывает значения в `NULL` или `0`, потому что обновляет только если есть хотя бы один non-NULL AVG. Это может оставить старые агрегаты.

### Средняя вероятность угрозы

После добавления/редактирования/удаления `threat_probabilities` вызывается:

```text
update_threat_probability(asset_id)
```

Она считает AVG(probability) и записывает в `assets.threat_probability`.

Важная особенность: если вероятность удалена последней, значение в `assets.threat_probability` не сбрасывается.

### Критичность

```text
criticality =
  life_health * 0.419 +
  economy * 0.252 +
  ecology * 0.099 +
  dependency * 0.144 +
  social * 0.051 +
  international * 0.035
```

Весовые коэффициенты лежат в `criteria_weights`.

### Impact

```text
impact = 1 + (criticality / 10) * 2
```

При шкале критичности 0-10 impact находится примерно в диапазоне 1-3.

### Первоначальный риск

```text
risk_score = impact * probability
```

Вероятность задается по шкале 1-3. Поэтому risk_score ожидаемо в диапазоне 1-9.

### Остаточный риск

```text
residual_risk = risk_score * (1 - control_effectiveness)
```

Если `control_effectiveness` не задан, в `/criticality` используется `0`.

### Классификация

```text
1.0-3.9: Низкий, "Допустимый, контрольный"
4.0-6.9: Средний, "Требует мер по снижению"
иначе: Высокий, "Требует приоритетного устранения"
```

Особенность: значения ниже 1 тоже попадут в "Высокий", потому что ветка `else` обрабатывает все, что не входит в 1-6.9. При `control_effectiveness=1` остаточный риск может стать `0`, и тогда классификация будет "Высокий". Это логическая ошибка.

## 11. UI и шаблоны

### Layout

`templates/index.html`:

- основной layout;
- Tailwind CDN;
- навигация;
- отображение текущего пользователя;
- flash-блок;
- `block content`.

### Основные страницы

- `login.html` - форма входа.
- `users.html`, `add_user.html` - пользователи.
- `experts.html`, `add_expert.html`, `edit_expert.html` - эксперты.
- `assets.html`, `add_asset.html`, `edit_asset.html` - активы.
- `asset_evaluations.html`, `add_asset_evaluation.html`, `edit_asset_evaluation.html` - экспертные оценки активов.
- `threat_probabilities.html`, `add_threat_probability.html`, `edit_threat_probability.html` - вероятности угроз.
- `risk_analysis.html`, `add_risk_analysis.html`, `edit_risk_analysis.html` - анализ рисков.
- `criticality.html` - итоговый расчет, таблицы, heatmap.

### JavaScript

JS минимальный и встроен прямо в templates:

- `add_user.html` - показывает выбор эксперта только для role `expert`.
- `add_risk_analysis.html` и `edit_risk_analysis.html` - показывает выбор контроля только для меры "Минимизация рисков и выбор контролей".
- формы оценок дополнительно валидируются на клиенте.

## 12. Запуск

Разработка:

```bash
pip install -r requirements.txt
python app.py
```

URL:

```text
http://localhost:5000
```

Default admin:

```text
admin / <пароль из консоли при первом запуске, либо RISKFLOW_ADMIN_PASSWORD>
```

Заполнение справочников:

```bash
python add_threats.py
python populate_vulnerabilities.py
python populate_control_measures.py
```

Продакшн по документации:

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

или uWSGI + Nginx. Для продакшна документация рекомендует PostgreSQL вместо SQLite.

## 13. Тесты и проверка

Автотестов, `pytest.ini`, `tox.ini`, `pyproject.toml` и test-файлов нет.

Выполненная проверка:

```bash
python -m py_compile app.py add_threats.py populate_vulnerabilities.py populate_control_measures.py
```

Синтаксических ошибок Python не найдено.

Ручная проверка по документации:

1. Запустить `python app.py`.
2. Войти как `admin` (пароль — из консоли при первом запуске, либо `RISKFLOW_ADMIN_PASSWORD`).
3. Добавить эксперта и пользователя.
4. Добавить актив.
5. От имени эксперта добавить оценки 0-10 и вероятность 1-3.
6. Добавить запись анализа рисков.
7. Проверить `/criticality`.

## 14. Сильные стороны

- Проект простой для запуска и понимания.
- Вся схема БД создается автоматически.
- Есть роли admin/expert.
- Пароли хэшируются.
- SQL-запросы параметризованы, базовая защита от SQL injection есть.
- Есть отдельные справочники угроз, уязвимостей и ISO-контролей.
- Расчеты рисков прозрачны и легко проверяются.
- Есть документация для запуска, архитектуры, пользователя и деплоя.

## 15. Основные риски и проблемы

### Критично для продакшна

- `app.secret_key` захардкожен.
- `debug=True` включен в `app.run`.
- ~~Default admin `admin/admin123` создается автоматически~~ — исправлено: пароль теперь случайный (или из `RISKFLOW_ADMIN_PASSWORD`), см. `app.py`.
- Нет CSRF-защиты для POST-форм.
- Нет rate limiting для login.
- SQLite-файл хранится в корне проекта.

### Данные и целостность

- Уникальность `(asset_id, expert_id)` для оценок и вероятностей проверяется только кодом, не БД.
- Foreign keys в SQLite объявлены, но `PRAGMA foreign_keys = ON` не включен.
- При удалении последней оценки/вероятности агрегаты в `assets` не сбрасываются.
- При редактировании оценки и смене `asset_id` пересчитывается только новый актив, старый актив остается со старым агрегатом.
- `/criticality` берет только одну `control_effectiveness` для актива через `fetchone()`, хотя у актива может быть несколько записей `risk_analysis`.
- `/update_risk_analysis/<asset_id>` обновляет все записи анализа риска для актива сразу, что может быть неожиданно.

### Логика риска

- `calculate_risk()` классифицирует `residual_risk < 1` как "Высокий", потому что это попадает в `else`.
- Heatmap boundaries `[1.0, 3.9, 6.9, 9.0]` плохо обрабатывают 0 и значения вне диапазона.
- Сортировка `ranked_risks` идет по criticality, а не по residual risk. Это может быть верно по задумке, но название "риски" может ожидать ранжирование по риску.

### Архитектура и сопровождение

- `app.py` слишком большой и смешивает все ответственности.
- Нет миграций БД.
- Нет конфигурации через переменные окружения.
- Нет централизованной функции подключения к БД.
- Много повторяющегося CRUD-кода.
- Нет серверной обработки `ValueError` для некоторых `float/int(request.form[...])`.
- Нет logging.
- Сгенерированные heatmap PNG не очищаются.
- Tailwind подключается через CDN, что зависит от сети.

## 16. Что улучшать первым

1. Вынести конфиг: `SECRET_KEY`, `DATABASE_PATH`, `DEBUG`.
2. Отключить default admin или заставить менять пароль.
3. Добавить CSRF-защиту, например Flask-WTF.
4. Включить SQLite foreign keys для каждого соединения.
5. Добавить UNIQUE constraints для `(asset_id, expert_id)` в `asset_evaluations` и `threat_probabilities`.
6. Исправить пересчет агрегатов при удалении/переносе оценок.
7. Исправить классификацию риска для `residual_risk < 1`.
8. Разделить `app.py` на модули: `db.py`, `auth.py`, `routes/`, `services/risk.py`.
9. Добавить тесты для расчетов и прав доступа.
10. Добавить очистку старых `static/heatmap_*.png`.

## 17. Где искать при будущих изменениях

- Расчет риска: `calculate_risk`, `/criticality`.
- Пересчет агрегатов: `update_asset_scores`, `update_threat_probability`.
- Права доступа: `login_required`, `admin_required`, `expert_required`.
- Схема БД и seed: `init_db`.
- CRUD активов: routes `/assets*`.
- CRUD экспертных оценок: routes `/asset_evaluations*`.
- CRUD вероятностей: routes `/threat_probabilities*`.
- CRUD анализа рисков: routes `/risk_analysis*`.
- UI отчета: `templates/criticality.html`.
- Layout и меню: `templates/index.html`.

## 18. Доработка ProcessRisk AI MVP

Добавлен первый процессный слой без удаления старой системы активов:

- таблицы `companies`, `processes`, `subprocesses`, `process_assets`, `process_bpmn`, `process_risks`;
- routes `/companies*`, `/processes*`, `/subprocesses*`, `/process_risks*`, `/process_report/<process_id>`;
- карточка процесса с описанием, входами, выходами, регуляторами, ресурсами, активами, подпроцессами, BPMN JSON и рисками;
- rule-based AI-рекомендации в `ai/risk_recommender.py`;
- seed-скрипт `seed_process_cases.py` для 3 демо-кейсов: управление ИБ-инцидентами, мониторинг SCADA, обработка персональных данных.
- отдельный отчет `/process_report/<process_id>` с описанием процесса, BPMN HTML-визуализацией из JSON, активами, подпроцессами, рисками, heatmap по процессным рискам, AI-рекомендациями и итоговым выводом.
- отдельная страница `/ai_analysis/<process_id>` с расширенным rule-based AI-анализом: рейтинг Low/Medium/High/Critical, score 0-9, топ-риск, слабые контроли, риски без контроля, повторяющиеся угрозы/уязвимости и приоритетные действия.
- улучшенный BPMN viewer в `templates/_bpmn_viewer.html`: SVG-диаграмма с автоматическим layout по уровням графа, визуальные узлы `start/task/gateway/end`, реальные curved arrows между связанными узлами, labels на связях, список связей в `details`, метаданные узлов/связей и preview на `/processes/<id>/bpmn`.
- для демо-кейса `Управление инцидентами ИБ` добавлена более сложная BPMN-модель с gateway `Критичный инцидент?`, веткой критичного реагирования, стандартным реагированием, post-incident review и финальным отчетом.

## 19. Автотесты

Добавлен базовый набор `unittest` без новых зависимостей:

- `tests/test_risk_calculation.py` - проверяет `calculate_risk`, включая исправленный диапазон `0-3.9` как низкий риск.
- `tests/test_ai_analysis.py` - проверяет rule-based рекомендации, топ-риск, повторяющиеся угрозы/уязвимости и риски без контроля.
- `tests/test_flask_process_flow.py` - использует временную SQLite-БД, логинится как admin, проверяет основные страницы `/companies`, `/processes`, `/processes/<id>`, `/process_report/<id>`, `/ai_analysis/<id>`, `/process_risks`, а также создание компании и процесса через routes.

Запуск:

```bash
python -m unittest discover -s tests -v
```

Текущий результат: 10 тестов проходят.

## 20. Risk-Oriented BPMN Формулы

Процессные риски расширены по логике статьи:

- `potentiality = probability + vulnerability_level - 1`
- `risk_level = potentiality * impact`
- `residual_risk = risk_level * (1 - control_effectiveness)`
- `risk_reduction = risk_level - residual_risk`
- `priority = HIGH / MEDIUM / LOW` на основе `risk_reduction`, ценности актива и `cost`

Реализация вынесена в `services/risk_service.py`, чтобы не держать все формулы в `app.py`.

В `process_risks` добавлены поля:

- `vulnerability_level`
- `cost`
- `risk_reduction`
- `priority`
- `risk_category`

Добавлен API для BPMN JSON:

- `GET /api/process_bpmn/<process_id>`
- `POST /api/process_bpmn/<process_id>`

Тесты расширены до 10 проверок: добавлены `tests/test_process_risk_service.py` и проверка BPMN API.

Исправления текущей системы:

- классификация риска теперь `0-3.9`, `4-6.9`, `7+`;
- при удалении последней оценки/вероятности агрегаты актива сбрасываются в `NULL`;
- при переносе оценки/вероятности пересчитываются старый и новый актив;
- добавлены UNIQUE индексы на `(asset_id, expert_id)` для оценок и вероятностей;
- все соединения приложения включают `PRAGMA foreign_keys = ON`;
- `/criticality` считает каждую запись `risk_analysis` отдельно, а итог по активу берет по максимальному остаточному риску.
