# Руководство по ролям, запуску и production-эксплуатации

Документ описывает текущую процессную версию RiskFlow AI: CSIRT-процессы, реестр пробелов, BPMN-подобные диаграммы, workflow, RBAC, compliance, audit log и rule-based рекомендации.

## 1. Быстрый запуск для разработки

### Требования

- Python 3.13 или совместимая версия Python 3.x
- pip
- SQLite 3
- Современный браузер

### macOS / Linux

```bash
cd /Users/tolegenajdynov/Desktop/nurusheva/risk_project
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Открыть:

```text
http://127.0.0.1:5000
```

Учетная запись по умолчанию:

```text
admin / <пароль печатается в консоли при первом запуске>
```

Чтобы задать пароль администратора самостоятельно вместо случайно сгенерированного, установите переменную окружения `RISKFLOW_ADMIN_PASSWORD` перед первым запуском.

### Windows

```powershell
cd path\to\risk_project
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

### Проверка

```bash
python -m pytest -q
```

Ожидаемый результат для текущей версии:

```text
99 passed
```

## 2. Первичная настройка

После первого входа под учётной записью `admin` (пароль см. в консоли при первом запуске, или заданный через `RISKFLOW_ADMIN_PASSWORD`):

1. Сменить пароль администратора.
2. Создать пользователей с ролями `risk_manager`, `process_owner`, `expert`, `auditor`.
3. Проверить справочники угроз, уязвимостей и мер контроля.
4. Создать организацию.
5. Создать CSIRT-процессы и подпроцессы.
6. Назначить владельцев процессов.
7. Создать BPMN-подобные диаграммы.
8. Добавить пробелы безопасности в реестр.
9. Создать меры обработки рисков.
10. Запустить workflow согласования.

## 3. Роли пользователей

### 3.1 Administrator

Назначение: полное администрирование системы.

Доступ:

- пользователи и роли;
- эксперты;
- организации;
- процессы и подпроцессы;
- BPMN-редактор;
- удаление ошибочных записей;
- audit log;
- data quality;
- CSV/ZIP-экспорт.

Рекомендуемый порядок работы:

```text
Пользователи -> Организации -> Процессы -> Подпроцессы -> BPMN -> Ответственные -> Data quality
```

Контрольные точки:

- у каждого процесса есть владелец;
- у критичных процессов есть BPMN-схема;
- у высоких рисков есть владелец, срок и мера обработки;
- изменения фиксируются в audit log.

### 3.2 Risk Manager

Назначение: управление реестром рисков, утверждение оценок и контроль обработки.

Доступ:

- просмотр всех процессов и рисков;
- создание и редактирование пробелов;
- утверждение и возврат рисков;
- запуск обработки;
- закрытие рисков;
- dashboard, workflow, responsibility matrix, operational analytics.

Типовой workflow:

```text
Draft -> submit -> In Review -> approve -> Approved -> start -> In Progress -> close -> Closed
```

Качественная запись риска должна иметь:

- описание пробела;
- связь с процессом и подпроцессом;
- значения `probability`, `vulnerability_level`, `impact`, `control_effectiveness`;
- `risk_owner` и `mitigation_owner`;
- `due_date`;
- evidence или комментарий;
- хотя бы одну меру обработки для высокого риска.

### 3.3 Process Owner

Назначение: владелец процесса, отвечает за фиксацию пробелов и выполнение мер.

Доступ:

- просмотр своих процессов;
- добавление пробелов по своим процессам;
- отправка риска на согласование;
- обновление статуса выполнения мер;
- добавление evidence;
- просмотр отчетов по своим процессам.

Практический сценарий:

```text
Открыть процесс -> Проверить BPMN -> Найти слабый шаг -> Добавить пробел -> Заполнить оценку -> Submit -> Выполнить меры -> Добавить evidence
```

Ограничения:

- не редактирует чужие процессы;
- не управляет пользователями;
- не удаляет системные записи;
- не утверждает риск вместо risk manager.

### 3.4 Expert

Назначение: экспертная оценка параметров риска.

Доступ:

- просмотр процессов и реестра пробелов;
- проверка параметров `P`, `V`, `I`, `CE`;
- участие в экспертной оценке;
- просмотр methodology и rule-based analysis;
- отправка риска на рассмотрение, если действие разрешено workflow.

Шкала оценки:

| Параметр | Шкала | Значение |
| --- | --- | --- |
| `P` probability | 0-3 | вероятность проявления угрозы |
| `V` vulnerability_level | 0-3 | выраженность уязвимости или организационного пробела |
| `I` impact | 0-9 | влияние на процесс реагирования |
| `CE` control_effectiveness | 0-1 | доля риска, закрываемая контролем |

Рекомендации эксперту:

- использовать evidence;
- не завышать все параметры одинаково;
- обосновывать высокие оценки;
- проверять связь риска с конкретным подпроцессом.

### 3.5 Auditor

Назначение: независимый контроль реестра, workflow и compliance.

Доступ:

- read-only просмотр процессов;
- read-only просмотр реестра рисков;
- workflow history;
- compliance dashboard;
- process reports;
- CSV-экспорт, если это разрешено политикой организации.

Что проверять:

- высокие риски без мер обработки;
- просроченные `due_date`;
- риски без владельца;
- меры без evidence;
- несоответствия compliance;
- полноту audit log;
- наличие BPMN-связи для критичных процессов.

## 4. End-to-end сценарий использования

### Шаг 1. Организация

Роль: `admin`.

```text
Организации -> Добавить -> Название -> Отрасль -> Описание -> Сохранить
```

### Шаг 2. CSIRT-процесс

Роль: `admin`.

```text
Процессы -> Добавить -> Организация -> Название -> Тип -> Владелец -> Сохранить
```

Примеры:

- обработка фишингового инцидента;
- реагирование на DDoS;
- управление уязвимостями;
- эскалация критичного инцидента;
- пост-инцидентный анализ.

### Шаг 3. Подпроцессы

Роль: `admin`.

```text
Процесс -> Добавить подпроцесс -> Название -> Ответственный -> Входы/выходы -> Сохранить
```

Пример цепочки:

```text
Получение события -> Triage -> Классификация -> Эскалация -> Containment -> Recovery -> Lessons learned
```

### Шаг 4. BPMN-подобная диаграмма

Роль: `admin`.

```text
Процесс -> BPMN -> Добавить start/task/gateway/end -> Связать задачи -> Сохранить
```

Рекомендации:

- каждая task должна соответствовать реальному подпроцессу;
- gateway использовать только для развилок;
- критичный путь должен быть понятен без дополнительных пояснений;
- после сохранения проверить качество модели.

### Шаг 5. Пробел безопасности

Роли: `admin`, `risk_manager`, `process_owner`.

```text
Реестр пробелов -> Добавить -> Процесс -> Шаг -> Описание -> P/V/I/CE -> Ответственные -> Срок -> Сохранить
```

Пример:

```text
В подпроцессе triage отсутствуют формальные критерии эскалации критичного инцидента.
```

### Шаг 6. Расчет риска

```text
P_event = max(P + V - 1, 0)
R_initial = P_event * I
R_residual = R_initial * (1 - CE)
```

Категории:

```text
0-3.9   -> Низкий
4.0-6.9 -> Средний
7.0+    -> Высокий
```

### Шаг 7. Мера обработки

Роли: `admin`, `risk_manager`, `process_owner`.

```text
Рекомендации -> Добавить -> Риск -> Мера -> Тип обработки -> Ответственный -> Срок -> Ожидаемый residual risk
```

Типы обработки:

- mitigate;
- transfer;
- accept;
- avoid.

### Шаг 8. Workflow

| Действие | Из | В | Кто выполняет |
| --- | --- | --- | --- |
| submit | Draft / Returned | In Review | admin, expert, process_owner, risk_manager |
| approve | In Review | Approved | admin, risk_manager |
| start | Approved | In Progress | admin, risk_manager, process_owner |
| close | In Progress / Approved | Closed | admin, risk_manager |
| return | In Review / Approved / In Progress | Returned | admin, risk_manager, process_owner |

### Шаг 9. Compliance

```text
Compliance -> Требование -> Evidence -> Статус -> Ответственный -> Сохранить
```

### Шаг 10. Отчеты

Доступные отчеты:

```text
/process_report/<id>
/process_risks/export.csv
/companies/<id>/report.zip
```

Для аудита и диссертации сохранять:

- HTML-отчет процесса;
- CSV реестра пробелов;
- ZIP-пакет организации;
- скриншоты dashboard и workflow;
- выгрузку audit log.

## 5. Production-level эксплуатация

`python app.py` использовать только для разработки. Для production нужен WSGI-сервер, reverse proxy, HTTPS, backup, logs и управление секретами.

### 5.1 Минимальная схема

```text
Browser -> HTTPS -> Nginx -> Gunicorn -> Flask app -> Database
                                      -> static/
                                      -> logs/
                                      -> backups/
```

### 5.2 Gunicorn

```bash
source .venv/bin/activate
pip install gunicorn
mkdir -p logs
gunicorn --workers 4 --bind 127.0.0.1:5000 --access-logfile logs/access.log --error-logfile logs/error.log app:app
```

### 5.3 systemd

Пример `/etc/systemd/system/riskflow.service`:

```ini
[Unit]
Description=RiskFlow AI Flask Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/riskflow
Environment="PATH=/opt/riskflow/.venv/bin"
Environment="FLASK_ENV=production"
ExecStart=/opt/riskflow/.venv/bin/gunicorn --workers 4 --bind 127.0.0.1:5000 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Команды:

```bash
sudo systemctl daemon-reload
sudo systemctl enable riskflow
sudo systemctl start riskflow
sudo systemctl status riskflow
```

### 5.4 Nginx

```nginx
server {
    listen 80;
    server_name riskflow.example.com;

    client_max_body_size 20M;

    location /static/ {
        alias /opt/riskflow/static/;
        expires 7d;
    }

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Проверка:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 5.5 HTTPS

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d riskflow.example.com
sudo certbot renew --dry-run
```

### 5.6 Security hardening

Перед production обязательно:

- сменить сгенерированный при первом запуске пароль admin на постоянный (или задать свой заранее через `RISKFLOW_ADMIN_PASSWORD`);
- вынести `app.secret_key` в переменную окружения;
- отключить Flask debug mode;
- включить HTTPS;
- закрыть доступ к `.db`, `.bak`, `.zip`;
- ограничить firewall;
- запускать приложение от отдельного Unix-пользователя;
- настроить backup;
- настроить логи;
- регулярно проверять audit log и data quality;
- формально утвердить матрицу ролей.

Рекомендуемая доработка кода:

```python
app.secret_key = os.environ.get("SECRET_KEY", "change-me-only-for-dev")
```

Генерация секрета:

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

### 5.7 База данных

SQLite подходит для демонстрации, пилота и малой команды. Для production с регулярной эксплуатацией рекомендуется PostgreSQL.

Backup SQLite:

```bash
mkdir -p backups
sqlite3 risk_assessment.db ".backup 'backups/risk_assessment_$(date +%Y%m%d_%H%M%S).db'"
```

Cron:

```cron
0 2 * * * cd /opt/riskflow && sqlite3 risk_assessment.db ".backup 'backups/risk_assessment_$(date +\%Y\%m\%d_\%H\%M\%S).db'"
```

Backup PostgreSQL:

```bash
pg_dump -U risk_user risk_assessment > backups/risk_assessment_$(date +%Y%m%d_%H%M%S).sql
```

### 5.8 Monitoring

Ежедневно:

- проверить `systemctl status riskflow`;
- проверить свежесть backup;
- проверить `logs/error.log`;
- проверить просроченные риски;
- проверить высокие риски без мер.

Еженедельно:

- экспортировать risk register;
- проверить audit log;
- проверить data quality;
- пересмотреть учетные записи.

Ежемесячно:

- пересмотреть высокие риски;
- обновить compliance evidence;
- обновить справочники угроз и уязвимостей;
- провести тест восстановления backup.

## 6. Production workflow организации

1. `Admin` создает структуру организации, роли и процессы.
2. `Process Owner` фиксирует пробелы по своим процессам.
3. `Expert` проверяет корректность оценок и evidence.
4. `Risk Manager` утверждает риск и назначает план обработки.
5. `Process Owner` выполняет меры и обновляет evidence.
6. `Risk Manager` закрывает риск после проверки.
7. `Auditor` проводит независимую проверку реестра, workflow и compliance.

## 7. Документы для реального внедрения

Для production-эксплуатации подготовить:

- матрицу ролей и полномочий;
- регламент создания и закрытия риска;
- методику оценки P/V/I/CE;
- регламент резервного копирования;
- регламент аудита изменений;
- шаблон отчета для руководства;
- инструкцию восстановления после сбоя;
- политику управления учетными записями.

## 8. Troubleshooting

### Порт 5000 занят

```bash
lsof -i :5000
kill <PID>
```

Или:

```bash
flask --app app run --port 5001
```

### Проверить пользователей

```bash
sqlite3 risk_assessment.db "SELECT username, role FROM users;"
```

### Создать таблицы

```bash
python app.py
```

`init_db()` создаст схему автоматически.

### Проверить static

```bash
ls -la static
chmod -R u+rw static
```

### Проверить зависимости

```bash
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```
