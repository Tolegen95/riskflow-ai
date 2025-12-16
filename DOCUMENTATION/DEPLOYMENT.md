# Руководство по развертыванию

## Развертывание для разработки

### Локальная разработка

1. **Клонирование/распаковка проекта**
```bash
cd risk_project
```

2. **Создание виртуального окружения (рекомендуется)**
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# или
venv\Scripts\activate  # Windows
```

3. **Установка зависимостей**
```bash
pip install -r requirements.txt
```

4. **Инициализация базы данных**
База данных создается автоматически при первом запуске.

5. **Заполнение справочников (опционально)**
```bash
python add_threats.py
python populate_vulnerabilities.py
python populate_control_measures.py
```

6. **Запуск приложения**
```bash
python app.py
```

Приложение будет доступно по адресу: `http://localhost:5000`

---

## Развертывание для продакшна

### Вариант 1: Использование Gunicorn

1. **Установка Gunicorn**
```bash
pip install gunicorn
```

2. **Запуск с Gunicorn**
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

Где:
- `-w 4` - количество воркеров
- `-b 0.0.0.0:5000` - адрес и порт
- `app:app` - модуль и приложение Flask

### Вариант 2: Использование uWSGI

1. **Установка uWSGI**
```bash
pip install uwsgi
```

2. **Создание конфигурационного файла `uwsgi.ini`**
```ini
[uwsgi]
module = app:app
master = true
processes = 4
socket = /tmp/risk_project.sock
chmod-socket = 666
vacuum = true
die-on-term = true
```

3. **Запуск**
```bash
uwsgi --ini uwsgi.ini
```

### Настройка Nginx

1. **Создание конфигурации Nginx**

Создайте файл `/etc/nginx/sites-available/risk_project`:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        include uwsgi_params;
        uwsgi_pass unix:/tmp/risk_project.sock;
    }

    location /static {
        alias /path/to/risk_project/static;
    }
}
```

2. **Активация конфигурации**
```bash
ln -s /etc/nginx/sites-available/risk_project /etc/nginx/sites-enabled/
nginx -t  # Проверка конфигурации
systemctl reload nginx
```

### Настройка HTTPS (SSL)

1. **Установка Certbot**
```bash
sudo apt-get install certbot python3-certbot-nginx
```

2. **Получение сертификата**
```bash
sudo certbot --nginx -d your-domain.com
```

3. **Автоматическое обновление**
```bash
sudo certbot renew --dry-run
```

---

## Миграция на PostgreSQL

### 1. Установка PostgreSQL

```bash
sudo apt-get install postgresql postgresql-contrib
```

### 2. Создание базы данных

```bash
sudo -u postgres psql
CREATE DATABASE risk_assessment;
CREATE USER risk_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE risk_assessment TO risk_user;
\q
```

### 3. Изменение кода

Замените в `app.py`:

```python
# Было:
import sqlite3
conn = sqlite3.connect('risk_assessment.db')

# Стало:
import psycopg2
conn = psycopg2.connect(
    host="localhost",
    database="risk_assessment",
    user="risk_user",
    password="your_password"
)
```

### 4. Установка драйвера

```bash
pip install psycopg2-binary
```

---

## Резервное копирование

### SQLite

```bash
# Простое копирование файла
cp risk_assessment.db backups/risk_assessment_$(date +%Y%m%d).db
```

### PostgreSQL

```bash
# Создание дампа
pg_dump -U risk_user risk_assessment > backup_$(date +%Y%m%d).sql

# Восстановление
psql -U risk_user risk_assessment < backup_20240101.sql
```

### Автоматическое резервное копирование

Создайте скрипт `backup.sh`:

```bash
#!/bin/bash
BACKUP_DIR="/path/to/backups"
DATE=$(date +%Y%m%d_%H%M%S)
cp risk_assessment.db "$BACKUP_DIR/risk_assessment_$DATE.db"
# Удаление старых бэкапов (старше 30 дней)
find "$BACKUP_DIR" -name "risk_assessment_*.db" -mtime +30 -delete
```

Добавьте в crontab:

```bash
0 2 * * * /path/to/backup.sh
```

---

## Мониторинг

### Логирование

Настройте логирование в `app.py`:

```python
import logging
from logging.handlers import RotatingFileHandler

if not app.debug:
    file_handler = RotatingFileHandler('logs/risk_project.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
```

### Мониторинг процессов

Используйте systemd для управления сервисом:

Создайте `/etc/systemd/system/risk_project.service`:

```ini
[Unit]
Description=Risk Assessment Application
After=network.target

[Service]
User=www-data
WorkingDirectory=/path/to/risk_project
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Активация:

```bash
sudo systemctl enable risk_project
sudo systemctl start risk_project
sudo systemctl status risk_project
```

---

## Безопасность

### Рекомендации

1. **Измените секретный ключ**
```python
app.secret_key = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
```

2. **Используйте переменные окружения**
```bash
export SECRET_KEY='your-secret-key'
export DATABASE_URL='postgresql://user:pass@localhost/db'
```

3. **Настройте firewall**
```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

4. **Регулярные обновления**
```bash
sudo apt-get update
sudo apt-get upgrade
```

---

## Масштабирование

### Горизонтальное масштабирование

1. Используйте несколько воркеров Gunicorn
2. Настройте балансировщик нагрузки (Nginx)
3. Используйте Redis для сессий (если нужно)

### Вертикальное масштабирование

1. Увеличьте количество воркеров
2. Используйте более мощный сервер
3. Оптимизируйте запросы к БД

---

## Устранение неполадок

### Проблема: Приложение не запускается

1. Проверьте установку зависимостей
2. Проверьте права доступа к файлам
3. Проверьте логи ошибок

### Проблема: База данных заблокирована

SQLite может блокироваться при одновременном доступе. Решение:
- Используйте PostgreSQL для продакшна
- Увеличьте timeout в настройках

### Проблема: Статические файлы не загружаются

1. Проверьте путь к папке `static/`
2. Настройте Nginx для обслуживания статики
3. Проверьте права доступа

---

## Поддержка

При возникновении проблем:
1. Проверьте логи приложения
2. Проверьте логи веб-сервера
3. Проверьте логи базы данных
4. Убедитесь, что все зависимости установлены

