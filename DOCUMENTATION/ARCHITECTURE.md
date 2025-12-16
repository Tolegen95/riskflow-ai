# Архитектура системы

## Обзор

Система оценки рисков построена на архитектуре **MVC (Model-View-Controller)** с использованием Flask как веб-фреймворка.

## Технологический стек

### Backend
- **Flask 2.0+** - веб-фреймворк
- **SQLite** - база данных
- **NumPy** - численные вычисления
- **Matplotlib/Seaborn** - визуализация данных

### Frontend
- **HTML5** - разметка
- **Tailwind CSS** - стилизация
- **JavaScript** - клиентская логика (минимальная)

## Структура приложения

```
app.py
├── Инициализация БД (init_db)
├── Функции расчета
│   ├── update_asset_scores()
│   ├── update_threat_probability()
│   └── calculate_risk()
├── Декораторы безопасности
│   ├── login_required
│   ├── admin_required
│   └── expert_required
└── Маршруты (Routes)
    ├── Аутентификация
    ├── Управление пользователями
    ├── Управление активами
    ├── Оценки
    └── Анализ рисков
```

## База данных

### Схема базы данных

#### Таблица: users
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT CHECK(role IN ('admin', 'expert')),
    expert_id INTEGER REFERENCES experts(id)
)
```

#### Таблица: experts
```sql
CREATE TABLE experts (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
)
```

#### Таблица: assets
```sql
CREATE TABLE assets (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    life_health REAL,
    economy REAL,
    ecology REAL,
    dependency REAL,
    social REAL,
    international REAL,
    threat_probability REAL
)
```

#### Таблица: asset_evaluations
```sql
CREATE TABLE asset_evaluations (
    id INTEGER PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id),
    expert_id INTEGER REFERENCES experts(id),
    life_health REAL,
    economy REAL,
    ecology REAL,
    dependency REAL,
    social REAL,
    international REAL
)
```

#### Таблица: threat_probabilities
```sql
CREATE TABLE threat_probabilities (
    id INTEGER PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id),
    expert_id INTEGER REFERENCES experts(id),
    probability REAL
)
```

#### Таблица: risk_analysis
```sql
CREATE TABLE risk_analysis (
    id INTEGER PRIMARY KEY,
    asset_id INTEGER REFERENCES assets(id),
    asset_owner_id INTEGER REFERENCES asset_owners(id),
    threat_id INTEGER REFERENCES threats(id),
    vulnerability_id INTEGER REFERENCES vulnerabilities(id),
    taken_measure_id INTEGER REFERENCES taken_measures(id),
    control_measure_id INTEGER REFERENCES control_measures(id),
    control_effectiveness REAL
)
```

### Связи между таблицами

```
users ──┬── expert_id ──> experts
        │
        └──> (через expert_id) ──> asset_evaluations
                                  threat_probabilities

assets <─── asset_evaluations
assets <─── threat_probabilities
assets <─── risk_analysis

experts <─── asset_evaluations
experts <─── threat_probabilities

threats ──> risk_analysis
vulnerabilities ──> risk_analysis
control_measures ──> risk_analysis
```

## Бизнес-логика

### Расчет критичности

```python
criticality = Σ(score_i × weight_i)
где:
  score_i - оценка по критерию i (0-10)
  weight_i - вес критерия i
```

### Расчет Impact

```python
impact = 1 + (criticality / 10) × 2
```

### Расчет риска

```python
initial_risk = impact × probability
residual_risk = initial_risk × (1 - control_effectiveness)
```

### Классификация риска

```python
if 1.0 <= residual_risk <= 3.9:
    level = "Низкий"
elif 4.0 <= residual_risk <= 6.9:
    level = "Средний"
else:  # 7.0 <= residual_risk <= 9.0
    level = "Высокий"
```

## Безопасность

### Аутентификация

1. **Хеширование паролей**: используется `werkzeug.security.generate_password_hash()`
2. **Сессии Flask**: хранение состояния пользователя
3. **Проверка паролей**: `check_password_hash()`

### Авторизация

Используются декораторы:
- `@login_required` - проверка входа
- `@admin_required` - только администратор
- `@expert_required` - администратор или эксперт

### Контроль доступа к данным

- Эксперты видят только свои оценки
- Администраторы видят все данные
- Проверка прав при редактировании/удалении

## Визуализация

### Тепловая карта

Используется библиотека Seaborn для создания тепловых карт:
- Данные: матрица [Impact, Residual Risk]
- Цветовая схема: зелено-желто-красная
- Границы: 1.0, 3.9, 6.9, 9.0

## Потоки данных

### Добавление оценки актива

```
1. Эксперт заполняет форму
2. POST запрос → add_asset_evaluation()
3. Валидация данных
4. Сохранение в БД
5. Автоматический пересчет средних оценок актива
6. Редирект на список оценок
```

### Расчет критичности

```
1. Запрос страницы criticality
2. Получение весов критериев из БД
3. Получение активов и их оценок
4. Расчет критичности для каждого актива
5. Расчет Impact
6. Расчет рисков
7. Генерация тепловой карты
8. Отображение результатов
```

## Обработка ошибок

- Валидация входных данных
- Проверка существования записей
- Обработка IntegrityError (дубликаты)
- Flash-сообщения для пользователя

## Производительность

### Оптимизации

1. **Индексы БД**: UNIQUE constraints на важных полях
2. **Кэширование**: сессии Flask
3. **Ленивая загрузка**: данные загружаются по запросу

### Ограничения

- SQLite подходит для небольших и средних проектов
- Для больших объемов данных рекомендуется PostgreSQL/MySQL

## Расширяемость

### Возможные улучшения

1. **API**: REST API для интеграции
2. **Экспорт данных**: CSV, Excel, PDF
3. **Уведомления**: email-уведомления
4. **История изменений**: аудит действий
5. **Многопользовательский режим**: одновременная работа
6. **Резервное копирование**: автоматические бэкапы БД

## Зависимости

```
Flask>=2.0.0          # Веб-фреймворк
matplotlib>=3.4.0     # Визуализация
seaborn>=0.11.0       # Тепловые карты
numpy>=1.21.0         # Численные вычисления
```

## Конфигурация

### Настройки приложения

- `app.secret_key` - ключ для сессий
- `debug=True` - режим отладки (для разработки)

### База данных

- Файл: `risk_assessment.db`
- Тип: SQLite
- Автоматическая инициализация при первом запуске

## Тестирование

Рекомендуется добавить:
- Unit-тесты для функций расчета
- Интеграционные тесты для маршрутов
- Тесты безопасности

## Развертывание

### Разработка
```bash
python app.py
```

### Продакшн
- Использовать WSGI сервер (Gunicorn, uWSGI)
- Настроить Nginx как reverse proxy
- Использовать PostgreSQL вместо SQLite
- Настроить HTTPS
- Регулярные бэкапы БД

