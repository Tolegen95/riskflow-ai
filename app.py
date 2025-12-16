# Set Matplotlib backend to Agg before importing pyplot
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import uuid
from matplotlib.colors import ListedColormap, BoundaryNorm

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Инициализация базы данных SQLite
def init_db():
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                life_health REAL,
                economy REAL,
                ecology REAL,
                dependency REAL,
                social REAL,
                international REAL,
                threat_probability REAL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'expert')),
                expert_id INTEGER,
                FOREIGN KEY (expert_id) REFERENCES experts(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS experts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS asset_evaluations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER,
                expert_id INTEGER,
                life_health REAL,
                economy REAL,
                ecology REAL,
                dependency REAL,
                social REAL,
                international REAL,
                FOREIGN KEY (asset_id) REFERENCES assets(id),
                FOREIGN KEY (expert_id) REFERENCES experts(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS criteria_weights (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                life_health REAL,
                economy REAL,
                ecology REAL,
                dependency REAL,
                social REAL,
                international REAL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_probabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER,
                expert_id INTEGER,
                probability REAL,
                FOREIGN KEY (asset_id) REFERENCES assets(id),
                FOREIGN KEY (expert_id) REFERENCES experts(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS asset_owners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                category TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS taken_measures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS control_measures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER,
                asset_owner_id INTEGER,
                threat_id INTEGER,
                vulnerability_id INTEGER,
                taken_measure_id INTEGER,
                control_measure_id INTEGER,
                control_effectiveness REAL,
                FOREIGN KEY (asset_id) REFERENCES assets(id),
                FOREIGN KEY (asset_owner_id) REFERENCES asset_owners(id),
                FOREIGN KEY (threat_id) REFERENCES threats(id),
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),
                FOREIGN KEY (taken_measure_id) REFERENCES taken_measures(id),
                FOREIGN KEY (control_measure_id) REFERENCES control_measures(id)
            )
        ''')
        # Проверяем, есть ли веса критериев, и добавляем фиксированные веса, если таблица пуста
        cursor.execute('SELECT COUNT(*) FROM criteria_weights')
        if cursor.fetchone()[0] == 0:
            cursor.execute('''
                INSERT INTO criteria_weights (life_health, economy, ecology, dependency, social, international)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (0.419, 0.252, 0.099, 0.144, 0.051, 0.035))
        # Добавляем начальные значения для реестров
        cursor.execute('SELECT COUNT(*) FROM asset_owners')
        if cursor.fetchone()[0] == 0:
            cursor.executemany('INSERT INTO asset_owners (name) VALUES (?)', [
                ('IT Department',), ('Operations',), ('Finance',)
            ])
        # cursor.execute('SELECT COUNT(*) FROM threats')
        # if cursor.fetchone()[0] == 0:
        #     cursor.executemany('INSERT INTO threats (name) VALUES (?)', [
        #         ('Cyber attack',), ('Physical attack',), ('Data breach',)
        #     ])
        cursor.execute('SELECT COUNT(*) FROM taken_measures')
        if cursor.fetchone()[0] == 0:
            cursor.executemany('INSERT INTO taken_measures (name) VALUES (?)', [
                ('Минимизация рисков и выбор контролей',),
                ('Передача рисков третьей стороне (страхование)',),
                ('Отказ от риска',),
                ('Принятие риска',)
            ])
        cursor.execute('SELECT COUNT(*) FROM control_measures')
        if cursor.fetchone()[0] == 0:
            cursor.executemany('INSERT INTO control_measures (name) VALUES (?)', [
                ('A.5.1.1 Policies for information Security',),
                ('A.5.1.2 Review of the policies for information security',),
                ('A.6.1.1 Information security roles and responsibilities',),
                ('A.6.1.2 Segregation of duties',),
                ('A.6.1.3 Contact with authorities',),
                ('A.6.1.4 Contact with special interest groups',)
            ])
        # Создаём администратора по умолчанию, если его нет
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = ?', ('admin',))
        if cursor.fetchone()[0] == 0:
            admin_password = generate_password_hash('admin123')
            cursor.execute('''
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
            ''', ('admin', admin_password, 'admin'))
        conn.commit()

init_db()

# Функция для пересчёта средних оценок для актива
def update_asset_scores(asset_id):
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT AVG(life_health), AVG(economy), AVG(ecology), AVG(dependency), AVG(social), AVG(international)
            FROM asset_evaluations
            WHERE asset_id = ?
        ''', (asset_id,))
        averages = cursor.fetchone()
        if averages and any(avg is not None for avg in averages):
            cursor.execute('''
                UPDATE assets
                SET life_health = ?, economy = ?, ecology = ?, dependency = ?, social = ?, international = ?
                WHERE id = ?
            ''', averages + (asset_id,))
            conn.commit()

# Функция для пересчёта средней вероятности угроз для актива
def update_threat_probability(asset_id):
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT AVG(probability)
            FROM threat_probabilities
            WHERE asset_id = ?
        ''', (asset_id,))
        avg_probability = cursor.fetchone()[0]
        if avg_probability is not None:
            cursor.execute('''
                UPDATE assets
                SET threat_probability = ?
                WHERE id = ?
            ''', (avg_probability, asset_id))
            conn.commit()

# Расчёт риска
def calculate_risk(impact, probability, control_effectiveness=None):
    risk_score = impact * probability
    if control_effectiveness is not None:
        residual_risk = risk_score * (1 - control_effectiveness)
    else:
        residual_risk = risk_score
    if 1 <= residual_risk <= 3.9:
        risk_level = "Низкий"
        risk_interpretation = "Допустимый, контрольный"
    elif 4 <= residual_risk <= 6.9:
        risk_level = "Средний"
        risk_interpretation = "Требует мер по снижению"
    else:
        risk_level = "Высокий"
        risk_interpretation = "Требует приоритетного устранения"
    return risk_score, residual_risk, risk_level, risk_interpretation

# Функции аутентификации
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему для доступа к этой странице.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему для доступа к этой странице.')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Доступ запрещён. Требуются права администратора.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def expert_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему для доступа к этой странице.')
            return redirect(url_for('login'))
        if session.get('role') not in ['admin', 'expert']:
            flash('Доступ запрещён. Требуются права эксперта.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Маршруты Flask
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with sqlite3.connect('risk_assessment.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, password_hash, role, expert_id FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[3]
                session['expert_id'] = user[4]
                flash(f'Добро пожаловать, {username}!')
                return redirect(url_for('index'))
            else:
                flash('Неверное имя пользователя или пароль.')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы успешно вышли из системы.')
    return redirect(url_for('login'))

@app.route('/users')
@admin_required
def list_users():
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.role, e.name
            FROM users u
            LEFT JOIN experts e ON u.expert_id = e.id
            ORDER BY u.role, u.username
        ''')
        users = cursor.fetchall()
    return render_template('users.html', users=users)

@app.route('/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM experts')
        experts = cursor.fetchall()
        
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']
            expert_id = request.form.get('expert_id', None)
            
            if expert_id:
                expert_id = int(expert_id) if expert_id else None
            else:
                expert_id = None
            
            if role == 'expert' and not expert_id:
                flash('Ошибка: для эксперта необходимо выбрать эксперта из списка!')
                return redirect(url_for('add_user'))
            
            password_hash = generate_password_hash(password)
            
            try:
                cursor.execute('''
                    INSERT INTO users (username, password_hash, role, expert_id)
                    VALUES (?, ?, ?, ?)
                ''', (username, password_hash, role, expert_id))
                conn.commit()
                flash('Пользователь успешно создан!')
                return redirect(url_for('list_users'))
            except sqlite3.IntegrityError:
                flash('Ошибка: пользователь с таким именем уже существует!')
                return redirect(url_for('add_user'))
    
    return render_template('add_user.html', experts=experts)

@app.route('/experts')
@admin_required
def list_experts():
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM experts')
        experts = cursor.fetchall()
    return render_template('experts.html', experts=experts)

@app.route('/experts/add', methods=['GET', 'POST'])
@admin_required
def add_expert():
    if request.method == 'POST':
        name = request.form['name']
        with sqlite3.connect('risk_assessment.db') as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO experts (name) VALUES (?)', (name,))
                conn.commit()
                flash('Эксперт успешно добавлен!')
                return redirect(url_for('list_experts'))
            except sqlite3.IntegrityError:
                flash('Ошибка: эксперт с таким именем уже существует!')
                return redirect(url_for('add_expert'))
    return render_template('add_expert.html')

@app.route('/experts/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_expert(id):
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        if request.method == 'POST':
            name = request.form['name']
            try:
                cursor.execute('UPDATE experts SET name = ? WHERE id = ?', (name, id))
                conn.commit()
                flash('Эксперт успешно отредактирован!')
                return redirect(url_for('list_experts'))
            except sqlite3.IntegrityError:
                flash('Ошибка: эксперт с таким именем уже существует!')
                return redirect(url_for('edit_expert', id=id))
        
        cursor.execute('SELECT id, name FROM experts WHERE id = ?', (id,))
        expert = cursor.fetchone()
        if not expert:
            flash('Эксперт не найден!')
            return redirect(url_for('list_experts'))
    return render_template('edit_expert.html', expert=expert)

@app.route('/experts/delete/<int:id>', methods=['POST'])
@admin_required
def delete_expert(id):
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM asset_evaluations WHERE expert_id = ?', (id,))
        eval_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM threat_probabilities WHERE expert_id = ?', (id,))
        prob_count = cursor.fetchone()[0]
        if eval_count > 0 or prob_count > 0:
            flash('Нельзя удалить эксперта, так как он имеет оценки активов или вероятности угроз!')
            return redirect(url_for('list_experts'))
        
        cursor.execute('SELECT id FROM experts WHERE id = ?', (id,))
        expert = cursor.fetchone()
        if not expert:
            flash('Эксперт не найден!')
            return redirect(url_for('list_experts'))
        
        cursor.execute('DELETE FROM experts WHERE id = ?', (id,))
        conn.commit()
        flash('Эксперт успешно удалён!')
    return redirect(url_for('list_experts'))

@app.route('/assets')
@login_required
def list_assets():
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, life_health, economy, ecology, dependency, social, international, threat_probability FROM assets')
        assets = cursor.fetchall()
    return render_template('assets.html', assets=assets)

@app.route('/assets/add', methods=['GET', 'POST'])
@admin_required
def add_asset():
    if request.method == 'POST':
        name = request.form['name']
        with sqlite3.connect('risk_assessment.db') as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO assets (name, life_health, economy, ecology, dependency, social, international, threat_probability)
                    VALUES (?, 0, 0, 0, 0, 0, 0, 0)
                ''', (name,))
                conn.commit()
                flash('Актив успешно добавлен! Пожалуйста, добавьте оценки экспертов и вероятности угроз.')
                return redirect(url_for('list_assets'))
            except sqlite3.IntegrityError:
                flash('Ошибка: актив с таким именем уже существует!')
                return redirect(url_for('add_asset'))
    return render_template('add_asset.html')

@app.route('/assets/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_asset(id):
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        if request.method == 'POST':
            name = request.form['name']
            try:
                cursor.execute('UPDATE assets SET name = ? WHERE id = ?', (name, id))
                conn.commit()
                flash('Название актива успешно отредактировано!')
                return redirect(url_for('list_assets'))
            except sqlite3.IntegrityError:
                flash('Ошибка: актив с таким именем уже существует!')
                return redirect(url_for('edit_asset', id=id))
        
        cursor.execute('SELECT id, name, life_health, economy, ecology, dependency, social, international, threat_probability FROM assets WHERE id = ?', (id,))
        asset = cursor.fetchone()
        if not asset:
            flash('Актив не найден!')
            return redirect(url_for('list_assets'))
    return render_template('edit_asset.html', asset=asset)

@app.route('/assets/delete/<int:id>', methods=['POST'])
@admin_required
def delete_asset(id):
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM asset_evaluations WHERE asset_id = ?', (id,))
        eval_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM threat_probabilities WHERE asset_id = ?', (id,))
        prob_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM risk_analysis WHERE asset_id = ?', (id,))
        risk_count = cursor.fetchone()[0]
        if eval_count > 0 or prob_count > 0 or risk_count > 0:
            flash('Нельзя удалить актив, так как он имеет оценки, вероятности угроз или записи анализа рисков!')
            return redirect(url_for('list_assets'))
        
        cursor.execute('SELECT id FROM assets WHERE id = ?', (id,))
        asset = cursor.fetchone()
        if not asset:
            flash('Актив не найден!')
            return redirect(url_for('list_assets'))
        
        cursor.execute('DELETE FROM assets WHERE id = ?', (id,))
        conn.commit()
        flash('Актив успешно удалён!')
    return redirect(url_for('list_assets'))

@app.route('/asset_evaluations')
@expert_required
def list_asset_evaluations():
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        if session.get('role') == 'admin':
            cursor.execute('''
                SELECT ae.id, a.name, e.name, ae.life_health, ae.economy, ae.ecology, ae.dependency, ae.social, ae.international
                FROM asset_evaluations ae
                JOIN assets a ON ae.asset_id = a.id
                JOIN experts e ON ae.expert_id = e.id
            ''')
        else:
            # Эксперты видят только свои оценки
            expert_id = session.get('expert_id')
            if not expert_id:
                flash('Ошибка: не найден ID эксперта для вашего аккаунта.')
                return redirect(url_for('index'))
            cursor.execute('''
                SELECT ae.id, a.name, e.name, ae.life_health, ae.economy, ae.ecology, ae.dependency, ae.social, ae.international
                FROM asset_evaluations ae
                JOIN assets a ON ae.asset_id = a.id
                JOIN experts e ON ae.expert_id = e.id
                WHERE ae.expert_id = ?
            ''', (expert_id,))
        evaluations = cursor.fetchall()
    return render_template('asset_evaluations.html', evaluations=evaluations)

@app.route('/asset_evaluations/add', methods=['GET', 'POST'])
@expert_required
def add_asset_evaluation():
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM assets')
        assets = cursor.fetchall()
        
        # Определяем expert_id в зависимости от роли
        if session.get('role') == 'admin':
            cursor.execute('SELECT id, name FROM experts')
            experts = cursor.fetchall()
            expert_id_from_form = True
        else:
            # Эксперты могут оценивать только от своего имени
            expert_id = session.get('expert_id')
            if not expert_id:
                flash('Ошибка: не найден ID эксперта для вашего аккаунта.')
                return redirect(url_for('index'))
            cursor.execute('SELECT id, name FROM experts WHERE id = ?', (expert_id,))
            experts = cursor.fetchall()
            expert_id_from_form = False
        
        if request.method == 'POST':
            asset_id = int(request.form['asset_id'])
            if expert_id_from_form:
                expert_id = int(request.form['expert_id'])
            else:
                expert_id = session.get('expert_id')
            life_health = float(request.form['life_health'])
            economy = float(request.form['economy'])
            ecology = float(request.form['ecology'])
            dependency = float(request.form['dependency'])
            social = float(request.form['social'])
            international = float(request.form['international'])
            
            scores = [life_health, economy, ecology, dependency, social, international]
            if any(score < 0 or score > 10 for score in scores):
                flash('Ошибка: значения должны быть в диапазоне от 0 до 10!')
                return redirect(url_for('add_asset_evaluation'))
            
            cursor.execute('SELECT COUNT(*) FROM asset_evaluations WHERE asset_id = ? AND expert_id = ?', (asset_id, expert_id))
            if cursor.fetchone()[0] > 0:
                flash('Ошибка: этот эксперт уже оценил данный актив!')
                return redirect(url_for('add_asset_evaluation'))
            
            cursor.execute('''
                INSERT INTO asset_evaluations (asset_id, expert_id, life_health, economy, ecology, dependency, social, international)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (asset_id, expert_id, life_health, economy, ecology, dependency, social, international))
            conn.commit()
            
            update_asset_scores(asset_id)
            flash('Оценка актива успешно добавлена!')
            return redirect(url_for('list_asset_evaluations'))
    
    return render_template('add_asset_evaluation.html', assets=assets, experts=experts)

@app.route('/asset_evaluations/edit/<int:id>', methods=['GET', 'POST'])
@expert_required
def edit_asset_evaluation(id):
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, asset_id, expert_id, life_health, economy, ecology, dependency, social, international
            FROM asset_evaluations WHERE id = ?
        ''', (id,))
        evaluation = cursor.fetchone()
        
        if not evaluation:
            flash('Оценка не найдена!')
            return redirect(url_for('list_asset_evaluations'))
        
        # Проверяем права доступа: эксперты могут редактировать только свои оценки
        if session.get('role') == 'expert':
            if evaluation[2] != session.get('expert_id'):
                flash('У вас нет прав для редактирования этой оценки!')
                return redirect(url_for('list_asset_evaluations'))
        
        cursor.execute('SELECT id, name FROM assets')
        assets = cursor.fetchall()
        
        if session.get('role') == 'admin':
            cursor.execute('SELECT id, name FROM experts')
            experts = cursor.fetchall()
            expert_id_from_form = True
        else:
            cursor.execute('SELECT id, name FROM experts WHERE id = ?', (evaluation[2],))
            experts = cursor.fetchall()
            expert_id_from_form = False
        
        if request.method == 'POST':
            asset_id = int(request.form['asset_id'])
            if expert_id_from_form:
                expert_id = int(request.form['expert_id'])
            else:
                expert_id = evaluation[2]  # Используем существующий expert_id
            life_health = float(request.form['life_health'])
            economy = float(request.form['economy'])
            ecology = float(request.form['ecology'])
            dependency = float(request.form['dependency'])
            social = float(request.form['social'])
            international = float(request.form['international'])
            
            scores = [life_health, economy, ecology, dependency, social, international]
            if any(score < 0 or score > 10 for score in scores):
                flash('Ошибка: значения должны быть в диапазоне от 0 до 10!')
                return redirect(url_for('edit_asset_evaluation', id=id))
            
            cursor.execute('SELECT COUNT(*) FROM asset_evaluations WHERE asset_id = ? AND expert_id = ? AND id != ?', (asset_id, expert_id, id))
            if cursor.fetchone()[0] > 0:
                flash('Ошибка: этот эксперт уже оценил данный актив!')
                return redirect(url_for('edit_asset_evaluation', id=id))
            
            cursor.execute('''
                UPDATE asset_evaluations
                SET asset_id = ?, expert_id = ?, life_health = ?, economy = ?, ecology = ?, dependency = ?, social = ?, international = ?
                WHERE id = ?
            ''', (asset_id, expert_id, life_health, economy, ecology, dependency, social, international, id))
            conn.commit()
            
            update_asset_scores(asset_id)
            flash('Оценка актива успешно отредактирована!')
            return redirect(url_for('list_asset_evaluations'))
    
    return render_template('edit_asset_evaluation.html', evaluation=evaluation, assets=assets, experts=experts)

@app.route('/asset_evaluations/delete/<int:id>', methods=['POST'])
@expert_required
def delete_asset_evaluation(id):
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT asset_id, expert_id FROM asset_evaluations WHERE id = ?', (id,))
        evaluation = cursor.fetchone()
        if not evaluation:
            flash('Оценка не найдена!')
            return redirect(url_for('list_asset_evaluations'))
        
        # Проверяем права доступа: эксперты могут удалять только свои оценки
        if session.get('role') == 'expert':
            if evaluation[1] != session.get('expert_id'):
                flash('У вас нет прав для удаления этой оценки!')
                return redirect(url_for('list_asset_evaluations'))
        
        cursor.execute('DELETE FROM asset_evaluations WHERE id = ?', (id,))
        conn.commit()
        
        update_asset_scores(evaluation[0])
        flash('Оценка актива успешно удалена!')
    return redirect(url_for('list_asset_evaluations'))

@app.route('/threat_probabilities')
@expert_required
def list_threat_probabilities():
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        if session.get('role') == 'admin':
            cursor.execute('''
                SELECT tp.id, a.name, e.name, tp.probability
                FROM threat_probabilities tp
                JOIN assets a ON tp.asset_id = a.id
                JOIN experts e ON tp.expert_id = e.id
            ''')
        else:
            # Эксперты видят только свои оценки
            expert_id = session.get('expert_id')
            if not expert_id:
                flash('Ошибка: не найден ID эксперта для вашего аккаунта.')
                return redirect(url_for('index'))
            cursor.execute('''
                SELECT tp.id, a.name, e.name, tp.probability
                FROM threat_probabilities tp
                JOIN assets a ON tp.asset_id = a.id
                JOIN experts e ON tp.expert_id = e.id
                WHERE tp.expert_id = ?
            ''', (expert_id,))
        probabilities = cursor.fetchall()
    return render_template('threat_probabilities.html', probabilities=probabilities)

@app.route('/threat_probabilities/add', methods=['GET', 'POST'])
@expert_required
def add_threat_probability():
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM assets')
        assets = cursor.fetchall()
        
        # Определяем expert_id в зависимости от роли
        if session.get('role') == 'admin':
            cursor.execute('SELECT id, name FROM experts')
            experts = cursor.fetchall()
            expert_id_from_form = True
        else:
            # Эксперты могут оценивать только от своего имени
            expert_id = session.get('expert_id')
            if not expert_id:
                flash('Ошибка: не найден ID эксперта для вашего аккаунта.')
                return redirect(url_for('index'))
            cursor.execute('SELECT id, name FROM experts WHERE id = ?', (expert_id,))
            experts = cursor.fetchall()
            expert_id_from_form = False
        
        if request.method == 'POST':
            asset_id = int(request.form['asset_id'])
            if expert_id_from_form:
                expert_id = int(request.form['expert_id'])
            else:
                expert_id = session.get('expert_id')
            probability = float(request.form['probability'])
            
            if probability < 1 or probability > 3:
                flash('Ошибка: вероятность должна быть в диапазоне от 1 до 3!')
                return redirect(url_for('add_threat_probability'))
            
            cursor.execute('SELECT COUNT(*) FROM threat_probabilities WHERE asset_id = ? AND expert_id = ?', (asset_id, expert_id))
            if cursor.fetchone()[0] > 0:
                flash('Ошибка: этот эксперт уже оценил вероятность угрозы для данного актива!')
                return redirect(url_for('add_threat_probability'))
            
            cursor.execute('''
                INSERT INTO threat_probabilities (asset_id, expert_id, probability)
                VALUES (?, ?, ?)
            ''', (asset_id, expert_id, probability))
            conn.commit()
            
            update_threat_probability(asset_id)
            flash('Вероятность угрозы успешно добавлена!')
            return redirect(url_for('list_threat_probabilities'))
    
    return render_template('add_threat_probability.html', assets=assets, experts=experts)

@app.route('/threat_probabilities/edit/<int:id>', methods=['GET', 'POST'])
@expert_required
def edit_threat_probability(id):
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, asset_id, expert_id, probability FROM threat_probabilities WHERE id = ?', (id,))
        probability = cursor.fetchone()
        
        if not probability:
            flash('Вероятность угрозы не найдена!')
            return redirect(url_for('list_threat_probabilities'))
        
        # Проверяем права доступа: эксперты могут редактировать только свои оценки
        if session.get('role') == 'expert':
            if probability[2] != session.get('expert_id'):
                flash('У вас нет прав для редактирования этой оценки!')
                return redirect(url_for('list_threat_probabilities'))
        
        cursor.execute('SELECT id, name FROM assets')
        assets = cursor.fetchall()
        
        if session.get('role') == 'admin':
            cursor.execute('SELECT id, name FROM experts')
            experts = cursor.fetchall()
            expert_id_from_form = True
        else:
            cursor.execute('SELECT id, name FROM experts WHERE id = ?', (probability[2],))
            experts = cursor.fetchall()
            expert_id_from_form = False
        
        if request.method == 'POST':
            asset_id = int(request.form['asset_id'])
            if expert_id_from_form:
                expert_id = int(request.form['expert_id'])
            else:
                expert_id = probability[2]  # Используем существующий expert_id
            new_probability = float(request.form['probability'])
            
            if new_probability < 1 or new_probability > 3:
                flash('Ошибка: вероятность должна быть в диапазоне от 1 до 3!')
                return redirect(url_for('edit_threat_probability', id=id))
            
            cursor.execute('SELECT COUNT(*) FROM threat_probabilities WHERE asset_id = ? AND expert_id = ? AND id != ?', (asset_id, expert_id, id))
            if cursor.fetchone()[0] > 0:
                flash('Ошибка: этот эксперт уже оценил вероятность угрозы для данного актива!')
                return redirect(url_for('edit_threat_probability', id=id))
            
            cursor.execute('''
                UPDATE threat_probabilities
                SET asset_id = ?, expert_id = ?, probability = ?
                WHERE id = ?
            ''', (asset_id, expert_id, new_probability, id))
            conn.commit()
            
            update_threat_probability(asset_id)
            flash('Вероятность угрозы успешно отредактирована!')
            return redirect(url_for('list_threat_probabilities'))
    
    return render_template('edit_threat_probability.html', probability=probability, assets=assets, experts=experts)

@app.route('/threat_probabilities/delete/<int:id>', methods=['POST'])
@expert_required
def delete_threat_probability(id):
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT asset_id, expert_id FROM threat_probabilities WHERE id = ?', (id,))
        probability = cursor.fetchone()
        if not probability:
            flash('Вероятность угрозы не найдена!')
            return redirect(url_for('list_threat_probabilities'))
        
        # Проверяем права доступа: эксперты могут удалять только свои оценки
        if session.get('role') == 'expert':
            if probability[1] != session.get('expert_id'):
                flash('У вас нет прав для удаления этой оценки!')
                return redirect(url_for('list_threat_probabilities'))
        
        cursor.execute('DELETE FROM threat_probabilities WHERE id = ?', (id,))
        conn.commit()
        
        update_threat_probability(probability[0])
        flash('Вероятность угрозы успешно удалена!')
    return redirect(url_for('list_threat_probabilities'))

@app.route('/risk_analysis')
@admin_required
def list_risk_analysis():
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ra.id, a.name, ao.name, t.name, v.name, v.category, tm.name, cm.name, ra.control_effectiveness
            FROM risk_analysis ra
            JOIN assets a ON ra.asset_id = a.id
            JOIN asset_owners ao ON ra.asset_owner_id = ao.id
            JOIN threats t ON ra.threat_id = t.id
            JOIN vulnerabilities v ON ra.vulnerability_id = v.id
            JOIN taken_measures tm ON ra.taken_measure_id = tm.id
            LEFT JOIN control_measures cm ON ra.control_measure_id = cm.id
        ''')
        risk_analyses = cursor.fetchall()
    return render_template('risk_analysis.html', risk_analyses=risk_analyses)

@app.route('/risk_analysis/add', methods=['GET', 'POST'])
@admin_required
def add_risk_analysis():
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM assets')
        assets = cursor.fetchall()
        cursor.execute('SELECT id, name FROM asset_owners')
        asset_owners = cursor.fetchall()
        cursor.execute('SELECT id, name FROM threats')
        threats = cursor.fetchall()
        cursor.execute('SELECT id, name, category FROM vulnerabilities ORDER BY category, name')
        vulnerabilities = cursor.fetchall()
        cursor.execute('SELECT id, name FROM taken_measures')
        taken_measures = cursor.fetchall()
        cursor.execute('SELECT id, name FROM control_measures')
        control_measures = cursor.fetchall()
        
        if request.method == 'POST':
            asset_id = int(request.form['asset_id'])
            asset_owner_id = int(request.form['asset_owner_id'])
            threat_id = int(request.form['threat_id'])
            vulnerability_id = int(request.form['vulnerability_id'])
            taken_measure_id = int(request.form['taken_measure_id'])
            control_measure_id = request.form.get('control_measure_id', None)
            control_effectiveness = request.form.get('control_effectiveness', None)
            
            if taken_measure_id:
                cursor.execute('SELECT name FROM taken_measures WHERE id = ?', (taken_measure_id,))
                taken_measure_name = cursor.fetchone()[0]
                if taken_measure_name != "Минимизация рисков и выбор контролей":
                    control_measure_id = None
            if control_effectiveness:
                try:
                    control_effectiveness = float(control_effectiveness)
                    if not (0 <= control_effectiveness <= 1):
                        flash('Ошибка: эффективность защиты должна быть в диапазоне от 0 до 1!')
                        return redirect(url_for('add_risk_analysis'))
                except (ValueError, TypeError):
                    flash('Ошибка: эффективность защиты должна быть числом!')
                    return redirect(url_for('add_risk_analysis'))
            
            cursor.execute('''
                INSERT INTO risk_analysis (asset_id, asset_owner_id, threat_id, vulnerability_id, taken_measure_id, control_measure_id, control_effectiveness)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (asset_id, asset_owner_id, threat_id, vulnerability_id, taken_measure_id, control_measure_id, control_effectiveness))
            conn.commit()
            
            flash('Запись анализа рисков успешно добавлена!')
            return redirect(url_for('list_risk_analysis'))
    
    return render_template('add_risk_analysis.html', assets=assets, asset_owners=asset_owners, threats=threats, vulnerabilities=vulnerabilities, taken_measures=taken_measures, control_measures=control_measures)

@app.route('/risk_analysis/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_risk_analysis(id):
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, asset_id, asset_owner_id, threat_id, vulnerability_id, taken_measure_id, control_measure_id, control_effectiveness
            FROM risk_analysis WHERE id = ?
        ''', (id,))
        risk_analysis = cursor.fetchone()
        cursor.execute('SELECT id, name FROM assets')
        assets = cursor.fetchall()
        cursor.execute('SELECT id, name FROM asset_owners')
        asset_owners = cursor.fetchall()
        cursor.execute('SELECT id, name FROM threats')
        threats = cursor.fetchall()
        cursor.execute('SELECT id, name, category FROM vulnerabilities ORDER BY category, name')
        vulnerabilities = cursor.fetchall()
        cursor.execute('SELECT id, name FROM taken_measures')
        taken_measures = cursor.fetchall()
        cursor.execute('SELECT id, name FROM control_measures')
        control_measures = cursor.fetchall()
        
        if not risk_analysis:
            flash('Запись анализа рисков не найдена!')
            return redirect(url_for('list_risk_analysis'))
        
        if request.method == 'POST':
            asset_id = int(request.form['asset_id'])
            asset_owner_id = int(request.form['asset_owner_id'])
            threat_id = int(request.form['threat_id'])
            vulnerability_id = int(request.form['vulnerability_id'])
            taken_measure_id = int(request.form['taken_measure_id'])
            control_measure_id = request.form.get('control_measure_id', None)
            control_effectiveness = request.form.get('control_effectiveness', None)
            
            if taken_measure_id:
                cursor.execute('SELECT name FROM taken_measures WHERE id = ?', (taken_measure_id,))
                taken_measure_name = cursor.fetchone()[0]
                if taken_measure_name != "Минимизация рисков и выбор контролей":
                    control_measure_id = None
            if control_effectiveness:
                try:
                    control_effectiveness = float(control_effectiveness)
                    if not (0 <= control_effectiveness <= 1):
                        flash('Ошибка: эффективность защиты должна быть в диапазоне от 0 до 1!')
                        return redirect(url_for('edit_risk_analysis', id=id))
                except (ValueError, TypeError):
                    flash('Ошибка: эффективность защиты должна быть числом!')
                    return redirect(url_for('edit_risk_analysis', id=id))
            
            cursor.execute('''
                UPDATE risk_analysis
                SET asset_id = ?, asset_owner_id = ?, threat_id = ?, vulnerability_id = ?, taken_measure_id = ?, control_measure_id = ?, control_effectiveness = ?
                WHERE id = ?
            ''', (asset_id, asset_owner_id, threat_id, vulnerability_id, taken_measure_id, control_measure_id, control_effectiveness, id))
            conn.commit()
            
            flash('Запись анализа рисков успешно отредактирована!')
            return redirect(url_for('list_risk_analysis'))
    
    return render_template('edit_risk_analysis.html', risk_analysis=risk_analysis, assets=assets, asset_owners=asset_owners, threats=threats, vulnerabilities=vulnerabilities, taken_measures=taken_measures, control_measures=control_measures)

@app.route('/risk_analysis/delete/<int:id>', methods=['POST'])
@admin_required
def delete_risk_analysis(id):
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM risk_analysis WHERE id = ?', (id,))
        risk_analysis = cursor.fetchone()
        if not risk_analysis:
            flash('Запись анализа рисков не найдена!')
            return redirect(url_for('list_risk_analysis'))
        
        cursor.execute('DELETE FROM risk_analysis WHERE id = ?', (id,))
        conn.commit()
        flash('Запись анализа рисков успешно удалена!')
    return redirect(url_for('list_risk_analysis'))

@app.route('/update_risk_analysis/<int:asset_id>', methods=['POST'])
@admin_required
def update_risk_analysis(asset_id):
    data = request.get_json()
    taken_measure_id = data.get('taken_measure_id')
    control_measure_id = data.get('control_measure_id')
    control_effectiveness = data.get('control_effectiveness')
    
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        if taken_measure_id:
            cursor.execute('SELECT name FROM taken_measures WHERE id = ?', (taken_measure_id,))
            taken_measure_name = cursor.fetchone()
            if taken_measure_name and taken_measure_name[0] != "Минимизация рисков и выбор контролей":
                control_measure_id = None
        if control_effectiveness:
            try:
                control_effectiveness = float(control_effectiveness)
                if not (0 <= control_effectiveness <= 1):
                    return jsonify({'success': False, 'error': 'Эффективность защиты должна быть в диапазоне от 0 до 1!'})
            except (ValueError, TypeError):
                return jsonify({'success': False, 'error': 'Эффективность защиты должна быть числом!'})
    
        cursor.execute('''
            UPDATE risk_analysis
            SET taken_measure_id = ?, control_measure_id = ?, control_effectiveness = ?
            WHERE asset_id = ?
        ''', (taken_measure_id, control_measure_id, control_effectiveness, asset_id))
        conn.commit()
    
    return jsonify({'success': True})

@app.route('/criticality')
@login_required
def criticality():
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT life_health, economy, ecology, dependency, social, international FROM criteria_weights')
        weights = cursor.fetchone()
        if not weights:
            flash('Ошибка: веса критериев не заданы!')
            return redirect(url_for('list_assets'))
        
        cursor.execute('SELECT id, name, life_health, economy, ecology, dependency, social, international, threat_probability FROM assets')
        assets = cursor.fetchall()
        
        risks_data = []
        for asset in assets:
            asset_id, name, *scores, threat_probability = asset
            if any(score is None for score in scores) or threat_probability is None:
                continue
            criticality = sum(score * weight for score, weight in zip(scores, weights))
            impact = 1 + (criticality / 10) * 2
            # Получаем эффективность защиты для данного актива
            cursor.execute('SELECT control_effectiveness FROM risk_analysis WHERE asset_id = ?', (asset_id,))
            control_effectiveness = cursor.fetchone()
            control_effectiveness = control_effectiveness[0] if control_effectiveness and control_effectiveness[0] is not None else 0
            risk_score, residual_risk, risk_level, risk_interpretation = calculate_risk(impact, threat_probability, control_effectiveness)
            risks_data.append((name, round(criticality, 2), round(impact, 2), round(threat_probability, 2), round(risk_score, 2), round(residual_risk, 2), risk_level, risk_interpretation))
        
        risks_data.sort(key=lambda x: x[1], reverse=True)
        ranked_risks = [(name, criticality, impact, prob, risk_score, residual_risk, risk_level, risk_interpretation, i + 1) for i, (name, criticality, impact, prob, risk_score, residual_risk, risk_level, risk_interpretation) in enumerate(risks_data)]
        
        # Получение данных анализа рисков
        cursor.execute('''
            SELECT ra.id, a.id, a.name, ao.name, t.name, v.name, v.category, ra.taken_measure_id, ra.control_measure_id, ra.control_effectiveness
            FROM risk_analysis ra
            JOIN assets a ON ra.asset_id = a.id
            JOIN asset_owners ao ON ra.asset_owner_id = ao.id
            JOIN threats t ON ra.threat_id = t.id
            JOIN vulnerabilities v ON ra.vulnerability_id = v.id
            JOIN taken_measures tm ON ra.taken_measure_id = tm.id
            LEFT JOIN control_measures cm ON ra.control_measure_id = cm.id
        ''')
        risk_analyses = cursor.fetchall()
        risk_analysis_data = []
        for idx, ra in enumerate(risk_analyses, 1):
            ra_id, asset_id, asset_name, asset_owner, threat, vulnerability, vuln_category, taken_measure_id, control_measure_id, control_effectiveness = ra
            # Получаем текстовые значения для taken_measure и control_measure
            cursor.execute('SELECT name FROM taken_measures WHERE id = ?', (taken_measure_id,))
            taken_measure_name = cursor.fetchone()[0]
            control_measure_name = None
            if control_measure_id:
                cursor.execute('SELECT name FROM control_measures WHERE id = ?', (control_measure_id,))
                control_measure_name = cursor.fetchone()[0]
            # Найти соответствующий риск для актива
            for risk in ranked_risks:
                if risk[0] == asset_name:
                    impact = risk[2]
                    likelihood = risk[3]
                    risk_score = risk[4]
                    residual_risk = risk[5]
                    # Объединяем название уязвимости и категорию
                    vulnerability_display = f"{vuln_category}: {vulnerability}"
                    risk_analysis_data.append((asset_id, idx, asset_name, asset_owner, threat, vulnerability_display, impact, likelihood, risk_score, taken_measure_name, control_measure_name, control_effectiveness or 0, residual_risk))
                    break
        
        # Генерация тепловой карты на основе остаточных рисков
        if ranked_risks:
            names = [asset[0] for asset in ranked_risks]
            impacts = [asset[2] for asset in ranked_risks]
            residual_risks = [asset[5] for asset in ranked_risks]
            data = np.array([impacts, residual_risks]).T
            filename = f"heatmap_{uuid.uuid4()}.png"
            
            # Определяем кастомную цветовую палитру для тепловой карты
            colors = ['#4CAF50', '#FFC107', '#F44336']  # Зелёный, Жёлтый, Красный
            boundaries = [1.0, 3.9, 6.9, 9.0]  # Границы для Низкий (1.0–3.9), Средний (4.0–6.9), Высокий (7.0–9.0)
            cmap = ListedColormap(colors)
            norm = BoundaryNorm(boundaries, cmap.N, clip=True)
            
            plt.figure(figsize=(8, 4))
            sns.heatmap(data, xticklabels=['Impact', 'Остаточный риск'], yticklabels=names, annot=True, cmap=cmap, norm=norm, cbar=False)
            plt.title("Тепловая карта остаточных рисков")
            plt.tight_layout()
            plt.savefig(os.path.join("static", filename))
            plt.close()
        else:
            filename = None
            flash('Нет данных для расчёта рисков! Убедитесь, что для активов заданы оценки и вероятности угроз.')
    
    return render_template('criticality.html', ranked_risks=ranked_risks, weights=weights, heatmap=filename, risk_analysis_data=risk_analysis_data)

if __name__ == '__main__':
    app.run(debug=True)