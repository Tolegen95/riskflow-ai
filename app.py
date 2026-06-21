# Set Matplotlib backend to Agg before importing pyplot
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response, has_request_context
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from decimal import Decimal, ROUND_DOWN, InvalidOperation
import csv
import io
import json
import sqlite3
import zipfile
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import uuid
import textwrap
import re
from matplotlib.colors import ListedColormap, BoundaryNorm
from ai.risk_recommender import analyze_process_risks, recommend_process_risk
from services.risk_service import calculate_process_risk_metrics, classify_numeric_risk

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE_PATH = 'risk_assessment.db'

USER_ROLES = [
    ('admin', 'Администратор'),
    ('expert', 'Эксперт'),
    ('process_owner', 'Владелец процесса'),
    ('risk_manager', 'Риск-менеджер'),
    ('auditor', 'Аудитор'),
]
USER_ROLE_LABELS = dict(USER_ROLES)
PROCESS_RISK_STATUSES = [
    'Draft', 'In Review', 'Approved', 'In Progress', 'Closed', 'Returned',
]
PROCESS_RISK_WORKFLOW_ACTIONS = {
    'submit': {
        'label': 'На согласование',
        'to_status': 'In Review',
        'from_statuses': ['Draft', 'Returned'],
        'roles': ['admin', 'expert', 'process_owner', 'risk_manager'],
    },
    'approve': {
        'label': 'Утвердить риск',
        'to_status': 'Approved',
        'from_statuses': ['In Review'],
        'roles': ['admin', 'risk_manager'],
    },
    'start': {
        'label': 'Начать обработку',
        'to_status': 'In Progress',
        'from_statuses': ['Approved'],
        'roles': ['admin', 'risk_manager', 'process_owner'],
    },
    'close': {
        'label': 'Закрыть риск',
        'to_status': 'Closed',
        'from_statuses': ['In Progress', 'Approved'],
        'roles': ['admin', 'risk_manager'],
    },
    'return': {
        'label': 'Вернуть на доработку',
        'to_status': 'Returned',
        'from_statuses': ['In Review', 'Approved', 'In Progress'],
        'roles': ['admin', 'risk_manager', 'process_owner'],
    },
}

@app.template_filter('role_label')
def role_label(value):
    return USER_ROLE_LABELS.get(value, value or '')

@app.template_filter('risk_number')
def risk_number(value, places=3):
    if value is None or value == '':
        return ''
    try:
        quant = Decimal('1').scaleb(-int(places))
        number = Decimal(str(value)).quantize(quant, rounding=ROUND_DOWN)
        return format(number.normalize(), 'f')
    except (InvalidOperation, ValueError, TypeError):
        return value

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def ensure_column(cursor, table_name, column_name, column_type):
    cursor.execute(f'PRAGMA table_info({table_name})')
    existing_columns = [row[1] for row in cursor.fetchall()]
    if column_name not in existing_columns:
        try:
            cursor.execute(f'ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}')
        except sqlite3.OperationalError as exc:
            if 'duplicate column name' not in str(exc).lower():
                raise

def migrate_users_role_constraint(conn, cursor):
    cursor.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'")
    row = cursor.fetchone()
    create_sql = row[0] if row else ''
    if "CHECK(role IN ('admin', 'expert'))" not in create_sql:
        return

    conn.commit()
    cursor.execute('PRAGMA foreign_keys = OFF')
    cursor.execute('ALTER TABLE users RENAME TO users_old_role_migration')
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'expert', 'process_owner', 'risk_manager', 'auditor')),
            expert_id INTEGER,
            FOREIGN KEY (expert_id) REFERENCES experts(id)
        )
    ''')
    cursor.execute('''
        INSERT INTO users (id, username, password_hash, role, expert_id)
        SELECT id, username, password_hash, role, expert_id
        FROM users_old_role_migration
    ''')
    cursor.execute('DROP TABLE users_old_role_migration')
    conn.commit()
    cursor.execute('PRAGMA foreign_keys = ON')

def rebuild_audit_log_table(conn, cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_log'")
    if not cursor.fetchone():
        return
    cursor.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'audit_log'")
    row = cursor.fetchone()
    if row and 'users_old_role_migration' not in (row[0] or ''):
        return

    conn.commit()
    cursor.execute('PRAGMA foreign_keys = OFF')
    cursor.execute('ALTER TABLE audit_log RENAME TO audit_log_old_fk_migration')
    cursor.execute('''
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            summary TEXT,
            before_data TEXT,
            after_data TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    cursor.execute('''
        INSERT INTO audit_log (id, user_id, username, action, entity_type, entity_id, summary, before_data, after_data, created_at)
        SELECT id, user_id, username, action, entity_type, entity_id, summary, before_data, after_data, created_at
        FROM audit_log_old_fk_migration
    ''')
    cursor.execute('DROP TABLE audit_log_old_fk_migration')
    conn.commit()
    cursor.execute('PRAGMA foreign_keys = ON')

def rebuild_process_risk_workflow_table(conn, cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'process_risk_workflow'")
    if not cursor.fetchone():
        return
    cursor.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'process_risk_workflow'")
    row = cursor.fetchone()
    if row and 'users_old_role_migration' not in (row[0] or ''):
        return

    conn.commit()
    cursor.execute('PRAGMA foreign_keys = OFF')
    cursor.execute('ALTER TABLE process_risk_workflow RENAME TO process_risk_workflow_old_fk_migration')
    cursor.execute('''
        CREATE TABLE process_risk_workflow (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            process_risk_id INTEGER NOT NULL,
            from_status TEXT,
            to_status TEXT NOT NULL,
            action TEXT NOT NULL,
            comment TEXT,
            user_id INTEGER,
            username TEXT,
            role TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (process_risk_id) REFERENCES process_risks(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    cursor.execute('''
        INSERT INTO process_risk_workflow (
            id, process_risk_id, from_status, to_status, action, comment,
            user_id, username, role, created_at
        )
        SELECT id, process_risk_id, from_status, to_status, action, comment,
               user_id, username, role, created_at
        FROM process_risk_workflow_old_fk_migration
    ''')
    cursor.execute('DROP TABLE process_risk_workflow_old_fk_migration')
    conn.commit()
    cursor.execute('PRAGMA foreign_keys = ON')

def seed_compliance_catalog(cursor):
    standards = [
        ('ISO/IEC 27001', '2022', 'Information security management system controls.'),
        ('IEC 62443', '4-2 / 3-3', 'Industrial automation and control system security for OT/IoT.'),
        ('NIST CSF', '2.0', 'Cybersecurity Framework functions and outcomes.'),
        ('NISTIR 8259', 'IoT Device Cybersecurity', 'IoT device cybersecurity capability baseline.'),
    ]
    standard_ids = {}
    for name, version, description in standards:
        cursor.execute('SELECT id FROM compliance_standards WHERE name = ?', (name,))
        row = cursor.fetchone()
        if row:
            standard_ids[name] = row[0]
            cursor.execute('UPDATE compliance_standards SET version = ?, description = ? WHERE id = ?', (version, description, row[0]))
        else:
            cursor.execute(
                'INSERT INTO compliance_standards (name, version, description) VALUES (?, ?, ?)',
                (name, version, description),
            )
            standard_ids[name] = cursor.lastrowid

    requirements = [
        ('ISO/IEC 27001', 'A.5.15', 'Access control', 'Define and enforce access control for systems and data.', 'Identity and Access'),
        ('ISO/IEC 27001', 'A.8.15', 'Logging', 'Produce and protect logs for security monitoring.', 'Monitoring'),
        ('ISO/IEC 27001', 'A.8.20', 'Network security', 'Secure network services and segregate sensitive network zones.', 'Network'),
        ('ISO/IEC 27001', 'A.8.24', 'Use of cryptography', 'Use cryptographic controls for confidentiality, integrity and authenticity.', 'Cryptography'),
        ('IEC 62443', 'SR 1.2', 'Software process and device identification', 'Identify and authenticate users, software processes and devices.', 'Identity and Access'),
        ('IEC 62443', 'SR 3.1', 'Communication integrity', 'Protect integrity of communicated information.', 'Network'),
        ('IEC 62443', 'SR 7.6', 'Network and security configuration settings', 'Restrict and manage security configuration changes.', 'Device Hardening'),
        ('NIST CSF', 'ID.AM-01', 'Asset inventory', 'Maintain inventory of hardware, software, systems and services.', 'Asset Management'),
        ('NIST CSF', 'PR.AA-01', 'Identity management', 'Manage identities and credentials for authorized users and devices.', 'Identity and Access'),
        ('NIST CSF', 'DE.CM-01', 'Continuous monitoring', 'Monitor networks and systems to find adverse events.', 'Monitoring'),
        ('NISTIR 8259', 'D-1', 'Device identification', 'IoT devices can be uniquely identified.', 'Asset Management'),
        ('NISTIR 8259', 'D-2', 'Device configuration', 'IoT device software and firmware configuration can be changed securely.', 'Device Hardening'),
        ('NISTIR 8259', 'D-3', 'Data protection', 'IoT devices protect stored and transmitted data.', 'Cryptography'),
        ('NISTIR 8259', 'D-4', 'Logical access', 'Logical access to IoT interfaces is restricted.', 'Identity and Access'),
        ('NISTIR 8259', 'D-5', 'Software update', 'IoT device software can be updated securely.', 'Firmware Security'),
    ]
    for standard_name, code, title, description, domain in requirements:
        standard_id = standard_ids[standard_name]
        cursor.execute('''
            INSERT INTO compliance_requirements (standard_id, code, title, description, domain)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(standard_id, code) DO UPDATE SET
                title = excluded.title,
                description = excluded.description,
                domain = excluded.domain
        ''', (standard_id, code, title, description, domain))

def migrate_process_risk_statuses(cursor):
    old_to_new = [
        (['In review', 'Owner approved'], 'In Review'),
        (['Mitigation planned'], 'Approved'),
        (['In progress', 'Mitigated', 'Accepted'], 'In Progress'),
    ]
    for old_statuses, new_status in old_to_new:
        placeholders = ','.join('?' * len(old_statuses))
        cursor.execute(
            f"UPDATE process_risks SET status = ? WHERE status IN ({placeholders})",
            [new_status] + old_statuses,
        )
        cursor.execute(
            f"UPDATE process_risk_workflow SET from_status = ? WHERE from_status IN ({placeholders})",
            [new_status] + old_statuses,
        )
        cursor.execute(
            f"UPDATE process_risk_workflow SET to_status = ? WHERE to_status IN ({placeholders})",
            [new_status] + old_statuses,
        )


def backfill_process_risk_metrics(cursor):
    cursor.execute('''
        SELECT pr.id, pr.probability, pr.vulnerability_level, pr.impact, pr.control_effectiveness,
               pr.cost, pr.asset_id,
               a.life_health, a.economy, a.ecology, a.dependency, a.social, a.international
        FROM process_risks pr
        LEFT JOIN assets a ON a.id = pr.asset_id
        WHERE pr.risk_reduction IS NULL OR pr.priority IS NULL OR pr.risk_category IS NULL
    ''')
    rows = cursor.fetchall()
    for row in rows:
        risk_id, probability, vulnerability_level, impact, control_effectiveness, cost = row[:6]
        values = [v for v in row[7:] if v is not None]
        asset_value = sum(values) / len(values) if values else 1
        metrics = calculate_process_risk_metrics(
            probability or 0,
            vulnerability_level if vulnerability_level is not None else 1,
            impact or 0,
            control_effectiveness or 0,
            cost or 0,
            asset_value,
        )
        risk_category = classify_numeric_risk(metrics['residual_risk'])
        cursor.execute('''
            UPDATE process_risks
            SET vulnerability_level = COALESCE(vulnerability_level, ?),
                initial_risk = ?,
                residual_risk = ?,
                risk_level = ?,
                risk_category = ?,
                cost = COALESCE(cost, ?),
                risk_reduction = ?,
                priority = ?
            WHERE id = ?
        ''', (
            vulnerability_level if vulnerability_level is not None else 1,
            metrics['risk_level'],
            metrics['residual_risk'],
            metrics['risk_level'],
            risk_category,
            cost or 0,
            metrics['risk_reduction'],
            metrics['priority'],
            risk_id,
        ))

# Инициализация базы данных SQLite
def init_db():
    with get_db_connection() as conn:
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
                role TEXT NOT NULL CHECK(role IN ('admin', 'expert', 'process_owner', 'risk_manager', 'auditor')),
                expert_id INTEGER,
                FOREIGN KEY (expert_id) REFERENCES experts(id)
            )
        ''')
        migrate_users_role_constraint(conn, cursor)
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
        cursor.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_evaluations_asset_expert
            ON asset_evaluations(asset_id, expert_id)
        ''')
        cursor.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_probabilities_asset_expert
            ON threat_probabilities(asset_id, expert_id)
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS companies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                industry TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                company_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                process_type TEXT,
                owner TEXT,
                input_data TEXT,
                output_data TEXT,
                regulations TEXT,
                resources TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (company_id) REFERENCES companies(id)
            )
        ''')
        ensure_column(cursor, 'processes', 'owner_user_id', 'INTEGER')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subprocesses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                input_data TEXT,
                output_data TEXT,
                responsible_person TEXT,
                used_systems TEXT,
                order_index INTEGER,
                FOREIGN KEY (process_id) REFERENCES processes(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS process_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_id INTEGER NOT NULL,
                asset_id INTEGER NOT NULL,
                role_in_process TEXT,
                FOREIGN KEY (process_id) REFERENCES processes(id),
                FOREIGN KEY (asset_id) REFERENCES assets(id)
            )
        ''')
        cursor.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_process_assets_process_asset
            ON process_assets(process_id, asset_id)
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS process_bpmn (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_id INTEGER NOT NULL,
                bpmn_json TEXT,
                bpmn_xml TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (process_id) REFERENCES processes(id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS process_risks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_id INTEGER NOT NULL,
                subprocess_id INTEGER,
                asset_id INTEGER,
                threat_id INTEGER,
                vulnerability_id INTEGER,
                control_measure_id INTEGER,
                risk_description TEXT,
                probability REAL,
                vulnerability_level REAL,
                impact REAL,
                initial_risk REAL,
                control_effectiveness REAL,
                residual_risk REAL,
                risk_level TEXT,
                cost REAL,
                risk_reduction REAL,
                priority TEXT,
                ai_recommendation TEXT,
                FOREIGN KEY (process_id) REFERENCES processes(id),
                FOREIGN KEY (subprocess_id) REFERENCES subprocesses(id),
                FOREIGN KEY (asset_id) REFERENCES assets(id),
                FOREIGN KEY (threat_id) REFERENCES threats(id),
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),
                FOREIGN KEY (control_measure_id) REFERENCES control_measures(id)
            )
        ''')
        ensure_column(cursor, 'process_risks', 'vulnerability_level', 'REAL')
        ensure_column(cursor, 'process_risks', 'cost', 'REAL')
        ensure_column(cursor, 'process_risks', 'risk_reduction', 'REAL')
        ensure_column(cursor, 'process_risks', 'priority', 'TEXT')
        ensure_column(cursor, 'process_risks', 'risk_category', 'TEXT')
        ensure_column(cursor, 'process_risks', 'status', "TEXT DEFAULT 'Draft'")
        ensure_column(cursor, 'process_risks', 'risk_owner', 'TEXT')
        ensure_column(cursor, 'process_risks', 'mitigation_owner', 'TEXT')
        ensure_column(cursor, 'process_risks', 'risk_owner_user_id', 'INTEGER')
        ensure_column(cursor, 'process_risks', 'mitigation_owner_user_id', 'INTEGER')
        ensure_column(cursor, 'process_risks', 'due_date', 'TEXT')
        ensure_column(cursor, 'process_risks', 'assessment_source', "TEXT DEFAULT 'Expert'")
        ensure_column(cursor, 'process_risks', 'confidence', "TEXT DEFAULT 'Medium'")
        ensure_column(cursor, 'process_risks', 'evidence', 'TEXT')
        ensure_column(cursor, 'process_risks', 'last_reviewed_at', 'TEXT')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS process_risk_expert_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_risk_id INTEGER NOT NULL,
                expert_id INTEGER NOT NULL,
                probability REAL NOT NULL,
                vulnerability_level REAL NOT NULL,
                impact REAL NOT NULL,
                control_effectiveness REAL,
                confidence TEXT DEFAULT 'Medium',
                evidence TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (process_risk_id) REFERENCES process_risks(id),
                FOREIGN KEY (expert_id) REFERENCES experts(id)
            )
        ''')
        cursor.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_process_risk_expert_assessments_risk_expert
            ON process_risk_expert_assessments(process_risk_id, expert_id)
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id INTEGER,
                summary TEXT,
                before_data TEXT,
                after_data TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        rebuild_audit_log_table(conn, cursor)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_treatment_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_risk_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                treatment_type TEXT DEFAULT 'Mitigate',
                owner TEXT,
                due_date TEXT,
                cost REAL,
                expected_residual_risk REAL,
                actual_residual_risk REAL,
                progress INTEGER DEFAULT 0,
                status TEXT DEFAULT 'Planned',
                evidence TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (process_risk_id) REFERENCES process_risks(id)
            )
        ''')
        ensure_column(cursor, 'risk_treatment_actions', 'owner_user_id', 'INTEGER')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_standards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                version TEXT,
                description TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_requirements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                standard_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                domain TEXT,
                FOREIGN KEY (standard_id) REFERENCES compliance_standards(id),
                UNIQUE(standard_id, code)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requirement_id INTEGER NOT NULL,
                treatment_id INTEGER,
                status TEXT DEFAULT 'Not assessed',
                evidence TEXT,
                owner_user_id INTEGER,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (requirement_id) REFERENCES compliance_requirements(id),
                FOREIGN KEY (treatment_id) REFERENCES risk_treatment_actions(id),
                FOREIGN KEY (owner_user_id) REFERENCES users(id)
            )
        ''')
        seed_compliance_catalog(cursor)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS process_risk_workflow (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_risk_id INTEGER NOT NULL,
                from_status TEXT,
                to_status TEXT NOT NULL,
                action TEXT NOT NULL,
                comment TEXT,
                user_id INTEGER,
                username TEXT,
                role TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (process_risk_id) REFERENCES process_risks(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        rebuild_process_risk_workflow_table(conn, cursor)
        migrate_process_risk_statuses(cursor)
        backfill_process_risk_metrics(cursor)
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
    with get_db_connection() as conn:
        cursor = conn.cursor()
        before = fetch_asset_snapshot(cursor, asset_id)
        cursor.execute('''
            SELECT AVG(life_health), AVG(economy), AVG(ecology), AVG(dependency), AVG(social), AVG(international)
            FROM asset_evaluations
            WHERE asset_id = ?
        ''', (asset_id,))
        averages = cursor.fetchone()
        values = averages if averages and any(avg is not None for avg in averages) else (None, None, None, None, None, None)
        cursor.execute('''
            UPDATE assets
            SET life_health = ?, economy = ?, ecology = ?, dependency = ?, social = ?, international = ?
            WHERE id = ?
        ''', values + (asset_id,))
        after = fetch_asset_snapshot(cursor, asset_id)
        log_audit_event(
            cursor,
            'recalculate',
            'asset',
            asset_id,
            'Средние оценки актива пересчитаны по экспертным голосам.',
            before=before,
            after=after,
        )
        conn.commit()

# Функция для пересчёта средней вероятности угроз для актива
def update_threat_probability(asset_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        before = fetch_asset_snapshot(cursor, asset_id)
        cursor.execute('''
            SELECT AVG(probability)
            FROM threat_probabilities
            WHERE asset_id = ?
        ''', (asset_id,))
        avg_probability = cursor.fetchone()[0]
        cursor.execute('''
            UPDATE assets
            SET threat_probability = ?
            WHERE id = ?
        ''', (avg_probability, asset_id))
        after = fetch_asset_snapshot(cursor, asset_id)
        log_audit_event(
            cursor,
            'recalculate',
            'asset',
            asset_id,
            'Средняя вероятность угрозы актива пересчитана по экспертным голосам.',
            before=before,
            after=after,
        )
        conn.commit()

def update_process_risk_from_expert_assessments(cursor, process_risk_id):
    cursor.execute('''
        SELECT AVG(probability), AVG(vulnerability_level), AVG(impact), AVG(control_effectiveness)
        FROM process_risk_expert_assessments
        WHERE process_risk_id = ?
    ''', (process_risk_id,))
    averages = cursor.fetchone()
    if not averages or averages[0] is None:
        return

    cursor.execute('SELECT asset_id, cost FROM process_risks WHERE id = ?', (process_risk_id,))
    row = cursor.fetchone()
    if not row:
        return
    asset_value = get_asset_value(cursor, row[0])
    metrics = calculate_process_risk_metrics(
        averages[0] or 0,
        averages[1] or 0,
        averages[2] or 0,
        averages[3] or 0,
        row[1] or 0,
        asset_value,
    )
    risk_category = classify_numeric_risk(metrics['residual_risk'])
    recommendation = recommend_process_risk(metrics['residual_risk'], averages[3] or 0, True, risk_category, averages[1] or 0)
    cursor.execute('''
        UPDATE process_risks
        SET probability = ?, vulnerability_level = ?, impact = ?, control_effectiveness = ?,
            initial_risk = ?, residual_risk = ?, risk_level = ?, risk_category = ?,
            risk_reduction = ?, priority = ?, ai_recommendation = ?,
            assessment_source = 'Expert aggregate', confidence = 'Medium', last_reviewed_at = DATE('now')
        WHERE id = ?
    ''', (
        averages[0], averages[1], averages[2], averages[3] or 0,
        metrics['risk_level'], metrics['residual_risk'], metrics['risk_level'], risk_category,
        metrics['risk_reduction'], metrics['priority'], recommendation, process_risk_id
    ))

# Расчёт риска
def calculate_risk(impact, probability, control_effectiveness=None):
    risk_score = impact * probability
    if control_effectiveness is not None:
        residual_risk = risk_score * (1 - control_effectiveness)
    else:
        residual_risk = risk_score
    if 0 <= residual_risk <= 3.9:
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

def risk_editor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему для доступа к этой странице.')
            return redirect(url_for('login'))
        if session.get('role') not in ['admin', 'risk_manager', 'process_owner']:
            flash('Доступ запрещён. Требуются права редактора рисков.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def can_perform_workflow_action(status, action_key, role):
    action = PROCESS_RISK_WORKFLOW_ACTIONS.get(action_key)
    if not action or role not in action['roles']:
        return False
    return (status or 'Draft') in action['from_statuses']

def get_available_workflow_actions(status, role):
    return [
        (action_key, action['label'])
        for action_key, action in PROCESS_RISK_WORKFLOW_ACTIONS.items()
        if can_perform_workflow_action(status, action_key, role)
    ]

def current_user_id():
    return session.get('user_id') if has_request_context() else None

def can_view_all_data():
    return session.get('role') in ('admin', 'auditor', 'risk_manager')

def append_process_visibility_filter(where, params, process_alias='p'):
    if can_view_all_data():
        return
    user_id = current_user_id()
    where.append(f'''(
        {process_alias}.owner_user_id = ?
        OR EXISTS (
            SELECT 1 FROM process_risks vis_pr
            WHERE vis_pr.process_id = {process_alias}.id
              AND (vis_pr.risk_owner_user_id = ? OR vis_pr.mitigation_owner_user_id = ?)
        )
        OR EXISTS (
            SELECT 1 FROM process_risks vis_pr2
            JOIN risk_treatment_actions vis_rta ON vis_rta.process_risk_id = vis_pr2.id
            WHERE vis_pr2.process_id = {process_alias}.id
              AND vis_rta.owner_user_id = ?
        )
    )''')
    params.extend([user_id, user_id, user_id, user_id])

def append_process_risk_visibility_filter(where, params, process_alias='p', risk_alias='pr'):
    if can_view_all_data():
        return
    user_id = current_user_id()
    where.append(f'''(
        {process_alias}.owner_user_id = ?
        OR {risk_alias}.risk_owner_user_id = ?
        OR {risk_alias}.mitigation_owner_user_id = ?
        OR EXISTS (
            SELECT 1 FROM risk_treatment_actions vis_rta
            WHERE vis_rta.process_risk_id = {risk_alias}.id
              AND vis_rta.owner_user_id = ?
        )
    )''')
    params.extend([user_id, user_id, user_id, user_id])

def append_treatment_visibility_filter(where, params, process_alias='p', risk_alias='pr', treatment_alias='rta'):
    if can_view_all_data():
        return
    user_id = current_user_id()
    where.append(f'''(
        {process_alias}.owner_user_id = ?
        OR {risk_alias}.risk_owner_user_id = ?
        OR {risk_alias}.mitigation_owner_user_id = ?
        OR {treatment_alias}.owner_user_id = ?
    )''')
    params.extend([user_id, user_id, user_id, user_id])

def user_can_view_process(cursor, process_id):
    if can_view_all_data():
        return True
    where = ['p.id = ?']
    params = [process_id]
    append_process_visibility_filter(where, params, 'p')
    cursor.execute(f"SELECT 1 FROM processes p WHERE {' AND '.join(where)} LIMIT 1", params)
    return cursor.fetchone() is not None

def user_can_edit_process_risk(cursor, risk_id):
    if session.get('role') == 'admin':
        return True
    if session.get('role') == 'risk_manager':
        return True
    if session.get('role') == 'expert':
        return True
    if session.get('role') not in ('process_owner',):
        return False
    user_id = current_user_id()
    cursor.execute('''
        SELECT 1
        FROM process_risks pr
        JOIN processes p ON p.id = pr.process_id
        WHERE pr.id = ?
          AND (pr.risk_owner_user_id = ? OR pr.mitigation_owner_user_id = ? OR p.owner_user_id = ?)
        LIMIT 1
    ''', (risk_id, user_id, user_id, user_id))
    return cursor.fetchone() is not None

def user_can_edit_treatment(cursor, treatment_id):
    if session.get('role') == 'admin':
        return True
    if session.get('role') not in ('risk_manager', 'process_owner'):
        return False
    user_id = current_user_id()
    cursor.execute('''
        SELECT 1
        FROM risk_treatment_actions rta
        JOIN process_risks pr ON pr.id = rta.process_risk_id
        JOIN processes p ON p.id = pr.process_id
        WHERE rta.id = ?
          AND (rta.owner_user_id = ? OR pr.mitigation_owner_user_id = ? OR p.owner_user_id = ?)
        LIMIT 1
    ''', (treatment_id, user_id, user_id, user_id))
    return cursor.fetchone() is not None

def row_to_dict(columns, row):
    if row is None:
        return None
    return {column: row[index] for index, column in enumerate(columns)}

def fetch_asset_snapshot(cursor, asset_id):
    columns = [
        'id', 'name', 'life_health', 'economy', 'ecology', 'dependency',
        'social', 'international', 'threat_probability'
    ]
    cursor.execute(f"SELECT {', '.join(columns)} FROM assets WHERE id = ?", (asset_id,))
    return row_to_dict(columns, cursor.fetchone())

def log_audit_event(cursor, action, entity_type, entity_id=None, summary='', before=None, after=None):
    user_id = session.get('user_id') if has_request_context() else None
    username = session.get('username') if has_request_context() else None
    cursor.execute('''
        INSERT INTO audit_log (user_id, username, action, entity_type, entity_id, summary, before_data, after_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        user_id,
        username,
        action,
        entity_type,
        entity_id,
        summary,
        json.dumps(before, ensure_ascii=False, default=str) if before is not None else None,
        json.dumps(after, ensure_ascii=False, default=str) if after is not None else None,
    ))

def fetch_process_risk_snapshot(cursor, risk_id):
    columns = [
        'id', 'process_id', 'subprocess_id', 'asset_id', 'threat_id', 'vulnerability_id',
        'control_measure_id', 'risk_description', 'probability', 'vulnerability_level',
        'impact', 'initial_risk', 'control_effectiveness', 'residual_risk', 'risk_level',
        'risk_category', 'cost', 'risk_reduction', 'priority', 'ai_recommendation',
        'status', 'risk_owner', 'mitigation_owner', 'due_date', 'assessment_source',
        'confidence', 'evidence', 'last_reviewed_at', 'risk_owner_user_id', 'mitigation_owner_user_id'
    ]
    cursor.execute(f"SELECT {', '.join(columns)} FROM process_risks WHERE id = ?", (risk_id,))
    return row_to_dict(columns, cursor.fetchone())

def fetch_asset_evaluation_snapshot(cursor, evaluation_id):
    columns = [
        'id', 'asset_id', 'expert_id', 'life_health', 'economy', 'ecology',
        'dependency', 'social', 'international'
    ]
    cursor.execute(f"SELECT {', '.join(columns)} FROM asset_evaluations WHERE id = ?", (evaluation_id,))
    return row_to_dict(columns, cursor.fetchone())

def fetch_threat_probability_snapshot(cursor, probability_id):
    columns = ['id', 'asset_id', 'expert_id', 'probability']
    cursor.execute(f"SELECT {', '.join(columns)} FROM threat_probabilities WHERE id = ?", (probability_id,))
    return row_to_dict(columns, cursor.fetchone())

def fetch_process_risk_assessment_snapshot(cursor, assessment_id):
    columns = [
        'id', 'process_risk_id', 'expert_id', 'probability', 'vulnerability_level',
        'impact', 'control_effectiveness', 'confidence', 'evidence', 'created_at'
    ]
    cursor.execute(f"SELECT {', '.join(columns)} FROM process_risk_expert_assessments WHERE id = ?", (assessment_id,))
    return row_to_dict(columns, cursor.fetchone())

def fetch_risk_treatment_snapshot(cursor, treatment_id):
    columns = [
        'id', 'process_risk_id', 'title', 'description', 'treatment_type', 'owner',
        'due_date', 'cost', 'expected_residual_risk', 'actual_residual_risk',
        'progress', 'status', 'evidence', 'created_at', 'updated_at', 'owner_user_id'
    ]
    cursor.execute(f"SELECT {', '.join(columns)} FROM risk_treatment_actions WHERE id = ?", (treatment_id,))
    return row_to_dict(columns, cursor.fetchone())

# Маршруты Flask
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('methodology'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', dashboard=load_dashboard_data())

@app.route('/methodology')
@login_required
def methodology():
    return render_template('methodology.html')

@app.route('/user_guide')
@login_required
def user_guide():
    return render_template('user_guide.html')

@app.route('/audit_log')
@admin_required
def audit_log():
    filters = {
        'entity_type': request.args.get('entity_type', ''),
        'action': request.args.get('action', ''),
        'username': request.args.get('username', '').strip(),
    }
    where = []
    params = []
    if filters['entity_type']:
        where.append('entity_type = ?')
        params.append(filters['entity_type'])
    if filters['action']:
        where.append('action = ?')
        params.append(filters['action'])
    if filters['username']:
        where.append('username LIKE ?')
        params.append(f"%{filters['username']}%")
    where_sql = f"WHERE {' AND '.join(where)}" if where else ''

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(f'''
            SELECT id, created_at, username, action, entity_type, entity_id, summary, before_data, after_data
            FROM audit_log
            {where_sql}
            ORDER BY created_at DESC, id DESC
            LIMIT 300
        ''', params)
        events = cursor.fetchall()
        cursor.execute('SELECT DISTINCT entity_type FROM audit_log ORDER BY entity_type')
        entity_types = [row[0] for row in cursor.fetchall()]
        cursor.execute('SELECT DISTINCT action FROM audit_log ORDER BY action')
        actions = [row[0] for row in cursor.fetchall()]
    return render_template('audit_log.html', events=events, filters=filters, entity_types=entity_types, actions=actions)

@app.route('/data_quality')
@admin_required
def data_quality():
    checks = load_data_quality_checks()
    summary = {
        'total_findings': sum(len(check['items']) for check in checks),
        'critical_findings': sum(len(check['items']) for check in checks if check['severity'] == 'critical'),
        'warning_findings': sum(len(check['items']) for check in checks if check['severity'] == 'warning'),
        'ok_checks': sum(1 for check in checks if not check['items']),
    }
    return render_template('data_quality.html', checks=checks, summary=summary)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with get_db_connection() as conn:
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
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.role, e.name
            FROM users u
            LEFT JOIN experts e ON u.expert_id = e.id
            ORDER BY u.role, u.username
        ''')
        users = cursor.fetchall()
    return render_template('users.html', users=users, role_labels=USER_ROLE_LABELS)

@app.route('/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM experts')
        experts = cursor.fetchall()
        
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']
            expert_id = request.form.get('expert_id', None)

            if role not in USER_ROLE_LABELS:
                flash('Ошибка: некорректная роль пользователя!')
                return redirect(url_for('add_user'))
            
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
    
    return render_template('user_form.html', user=None, experts=experts, roles=USER_ROLES)

@app.route('/users/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_user(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM experts ORDER BY name')
        experts = cursor.fetchall()

        cursor.execute('SELECT id, username, role, expert_id FROM users WHERE id = ?', (id,))
        user = cursor.fetchone()
        if not user:
            flash('Пользователь не найден!')
            return redirect(url_for('list_users'))

        if request.method == 'POST':
            username = request.form['username'].strip()
            password = request.form.get('password', '')
            role = request.form['role']
            expert_id = request.form.get('expert_id') or None

            if role not in USER_ROLE_LABELS:
                flash('Ошибка: некорректная роль пользователя!')
                return redirect(url_for('edit_user', id=id))

            if expert_id:
                expert_id = int(expert_id)

            if role == 'expert' and not expert_id:
                flash('Ошибка: для эксперта необходимо выбрать эксперта из списка!')
                return redirect(url_for('edit_user', id=id))

            if role != 'expert':
                expert_id = None

            if user[2] == 'admin' and role != 'admin':
                cursor.execute('SELECT COUNT(*) FROM users WHERE role = ?', ('admin',))
                if cursor.fetchone()[0] <= 1:
                    flash('Нельзя изменить роль последнего администратора!')
                    return redirect(url_for('edit_user', id=id))

            try:
                if password:
                    password_hash = generate_password_hash(password)
                    cursor.execute('''
                        UPDATE users
                        SET username = ?, password_hash = ?, role = ?, expert_id = ?
                        WHERE id = ?
                    ''', (username, password_hash, role, expert_id, id))
                else:
                    cursor.execute('''
                        UPDATE users
                        SET username = ?, role = ?, expert_id = ?
                        WHERE id = ?
                    ''', (username, role, expert_id, id))
                conn.commit()

                if session.get('user_id') == id:
                    session['username'] = username
                    session['role'] = role
                    session['expert_id'] = expert_id

                flash('Пользователь успешно отредактирован!')
                return redirect(url_for('list_users'))
            except sqlite3.IntegrityError:
                flash('Ошибка: пользователь с таким именем уже существует!')
                return redirect(url_for('edit_user', id=id))

    return render_template('user_form.html', user=user, experts=experts, roles=USER_ROLES)

@app.route('/users/delete/<int:id>', methods=['POST'])
@admin_required
def delete_user(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role FROM users WHERE id = ?', (id,))
        user = cursor.fetchone()
        if not user:
            flash('Пользователь не найден!')
            return redirect(url_for('list_users'))

        if session.get('user_id') == id:
            flash('Нельзя удалить текущего пользователя!')
            return redirect(url_for('list_users'))

        if user[2] == 'admin':
            cursor.execute('SELECT COUNT(*) FROM users WHERE role = ?', ('admin',))
            if cursor.fetchone()[0] <= 1:
                flash('Нельзя удалить последнего администратора!')
                return redirect(url_for('list_users'))

        cursor.execute('DELETE FROM users WHERE id = ?', (id,))
        conn.commit()
        flash('Пользователь успешно удалён!')

    return redirect(url_for('list_users'))

@app.route('/experts')
@admin_required
def list_experts():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM experts')
        experts = cursor.fetchall()
    return render_template('experts.html', experts=experts)

@app.route('/experts/add', methods=['GET', 'POST'])
@admin_required
def add_expert():
    if request.method == 'POST':
        name = request.form['name']
        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO experts (name) VALUES (?)', (name,))
                conn.commit()
                flash('Эксперт успешно добавлен!')
                return redirect(url_for('list_experts'))
            except sqlite3.IntegrityError:
                flash('Ошибка: эксперт с таким именем уже существует!')
                return redirect(url_for('add_expert'))
    return render_template('expert_form.html', expert=None)

@app.route('/experts/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_expert(id):
    with get_db_connection() as conn:
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
    return render_template('expert_form.html', expert=expert)

@app.route('/experts/delete/<int:id>', methods=['POST'])
@admin_required
def delete_expert(id):
    with get_db_connection() as conn:
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

@app.route('/companies')
@admin_required
def list_companies():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT c.id, c.name, c.industry, c.description, COUNT(p.id)
            FROM companies c
            LEFT JOIN processes p ON p.company_id = c.id
            GROUP BY c.id
            ORDER BY c.name
        ''')
        companies = cursor.fetchall()
    return render_template('companies.html', companies=companies)

@app.route('/companies/add', methods=['GET', 'POST'])
@admin_required
def add_company():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description')
        industry = request.form.get('industry')
        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('INSERT INTO companies (name, description, industry) VALUES (?, ?, ?)', (name, description, industry))
                conn.commit()
                flash('Компания успешно создана!')
                return redirect(url_for('list_companies'))
            except sqlite3.IntegrityError:
                flash('Ошибка: компания с таким именем уже существует!')
    return render_template('company_form.html', company=None)

@app.route('/companies/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_company(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, description, industry FROM companies WHERE id = ?', (id,))
        company = cursor.fetchone()
        if not company:
            flash('Компания не найдена!')
            return redirect(url_for('list_companies'))
        if request.method == 'POST':
            try:
                cursor.execute('UPDATE companies SET name = ?, description = ?, industry = ? WHERE id = ?', (
                    request.form['name'], request.form.get('description'), request.form.get('industry'), id
                ))
                conn.commit()
                flash('Компания успешно обновлена!')
                return redirect(url_for('list_companies'))
            except sqlite3.IntegrityError:
                flash('Ошибка: компания с таким именем уже существует!')
    return render_template('company_form.html', company=company)

@app.route('/companies/delete/<int:id>', methods=['POST'])
@admin_required
def delete_company(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM processes WHERE company_id = ?', (id,))
        if cursor.fetchone()[0] > 0:
            flash('Нельзя удалить компанию, у которой есть процессы!')
            return redirect(url_for('list_companies'))
        cursor.execute('DELETE FROM companies WHERE id = ?', (id,))
        conn.commit()
    flash('Компания удалена!')
    return redirect(url_for('list_companies'))

@app.route('/processes')
@login_required
def list_processes():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        where = []
        params = []
        append_process_visibility_filter(where, params, 'p')
        where_sql = f"WHERE {' AND '.join(where)}" if where else ''
        cursor.execute(f'''
            SELECT p.id, p.name, c.name, p.process_type, p.owner, COUNT(sp.id)
            FROM processes p
            JOIN companies c ON c.id = p.company_id
            LEFT JOIN subprocesses sp ON sp.process_id = p.id
            {where_sql}
            GROUP BY p.id
            ORDER BY c.name, p.name
        ''', params)
        processes = cursor.fetchall()
    return render_template('processes.html', processes=processes)

@app.route('/processes/add', methods=['GET', 'POST'])
@admin_required
def add_process():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM companies ORDER BY name')
        companies = cursor.fetchall()
        users = load_user_options(cursor)
        if request.method == 'POST':
            owner_user_id = request.form.get('owner_user_id') or None
            owner = request.form.get('owner')
            if owner_user_id and not owner:
                owner = get_user_display(cursor, owner_user_id)
            cursor.execute('''
                INSERT INTO processes (company_id, name, description, process_type, owner, owner_user_id, input_data, output_data, regulations, resources)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                int(request.form['company_id']), request.form['name'], request.form.get('description'),
                request.form.get('process_type'), owner, owner_user_id, request.form.get('input_data'),
                request.form.get('output_data'), request.form.get('regulations'), request.form.get('resources')
            ))
            conn.commit()
            flash('Процесс успешно создан!')
            return redirect(url_for('list_processes'))
    return render_template('process_form.html', process=None, companies=companies, users=users)

@app.route('/processes/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_process(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, company_id, name, description, process_type, owner, input_data, output_data, regulations, resources, owner_user_id FROM processes WHERE id = ?', (id,))
        process = cursor.fetchone()
        if not process:
            flash('Процесс не найден!')
            return redirect(url_for('list_processes'))
        if not user_can_view_process(cursor, id):
            flash('Доступ запрещён к этому процессу.')
            return redirect(url_for('list_processes'))
        cursor.execute('SELECT id, name FROM companies ORDER BY name')
        companies = cursor.fetchall()
        users = load_user_options(cursor)
        if request.method == 'POST':
            owner_user_id = request.form.get('owner_user_id') or None
            owner = request.form.get('owner')
            if owner_user_id and not owner:
                owner = get_user_display(cursor, owner_user_id)
            cursor.execute('''
                UPDATE processes
                SET company_id = ?, name = ?, description = ?, process_type = ?, owner = ?, owner_user_id = ?, input_data = ?, output_data = ?, regulations = ?, resources = ?
                WHERE id = ?
            ''', (
                int(request.form['company_id']), request.form['name'], request.form.get('description'),
                request.form.get('process_type'), owner, owner_user_id, request.form.get('input_data'),
                request.form.get('output_data'), request.form.get('regulations'), request.form.get('resources'), id
            ))
            conn.commit()
            flash('Процесс успешно обновлен!')
            return redirect(url_for('process_detail', id=id))
    return render_template('process_form.html', process=process, companies=companies, users=users)

@app.route('/processes/<int:id>')
@login_required
def process_detail(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT p.id, p.company_id, p.name, p.description, p.process_type, p.owner, p.input_data, p.output_data, p.regulations, p.resources, c.name
            FROM processes p
            JOIN companies c ON c.id = p.company_id
            WHERE p.id = ?
        ''', (id,))
        process = cursor.fetchone()
        if not process:
            flash('Процесс не найден!')
            return redirect(url_for('list_processes'))
        cursor.execute('SELECT id, name, description, input_data, output_data, responsible_person, used_systems, order_index FROM subprocesses WHERE process_id = ? ORDER BY COALESCE(order_index, 9999), id', (id,))
        subprocesses = cursor.fetchall()
        cursor.execute('SELECT id, bpmn_json FROM process_bpmn WHERE process_id = ? ORDER BY id DESC LIMIT 1', (id,))
        bpmn = cursor.fetchone()
        bpmn_model = parse_bpmn_json(bpmn[1] if bpmn else None)
        bpmn_subprocess_risks = get_bpmn_subprocess_risk_summary(cursor, id)
        bpmn_model = enrich_bpmn_model_with_risks(bpmn_model, bpmn_subprocess_risks)
        bpmn_business_context = build_bpmn_business_context(cursor, id, bpmn_model)
        bpmn_critical_path = build_bpmn_critical_path(bpmn_model)
        bpmn_quality = build_bpmn_quality_summary(bpmn_model, subprocesses)
        risk_where = ['pr.process_id = ?']
        risk_params = [id]
        append_process_risk_visibility_filter(risk_where, risk_params, 'p', 'pr')
        risk_where_sql = f"WHERE {' AND '.join(risk_where)}"
        cursor.execute(f'''
            SELECT pr.id, sp.name, NULL, NULL, NULL, pr.probability, pr.impact, pr.initial_risk,
                   pr.control_effectiveness, pr.residual_risk, COALESCE(pr.risk_category, pr.risk_level), pr.ai_recommendation,
                   pr.risk_reduction, pr.priority, COALESCE(pr.status, 'Draft')
            FROM process_risks pr
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            {risk_where_sql}
            ORDER BY pr.residual_risk DESC
        ''', risk_params)
        risks = cursor.fetchall()
    workflow_actions = {
        risk[0]: get_available_workflow_actions(risk[14], session.get('role'))
        for risk in risks
    }
    return render_template('process_detail.html', process=process, subprocesses=subprocesses, bpmn=bpmn, bpmn_model=bpmn_model, risks=risks, bpmn_subprocess_risks=bpmn_subprocess_risks, bpmn_business_context=bpmn_business_context, bpmn_critical_path=bpmn_critical_path, bpmn_quality=bpmn_quality, workflow_actions=workflow_actions, can_edit_risks=session.get('role') in ('admin', 'risk_manager', 'process_owner'))

@app.route('/processes/delete/<int:id>', methods=['POST'])
@admin_required
def delete_process(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM subprocesses WHERE process_id = ?', (id,))
        sub_count = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM process_risks WHERE process_id = ?', (id,))
        risk_count = cursor.fetchone()[0]
        if sub_count or risk_count:
            flash('Нельзя удалить процесс, у которого есть подпроцессы или риски!')
            return redirect(url_for('list_processes'))
        cursor.execute('DELETE FROM process_assets WHERE process_id = ?', (id,))
        cursor.execute('DELETE FROM process_bpmn WHERE process_id = ?', (id,))
        cursor.execute('DELETE FROM processes WHERE id = ?', (id,))
        conn.commit()
    flash('Процесс удален!')
    return redirect(url_for('list_processes'))

@app.route('/processes/<int:process_id>/assets/add', methods=['POST'])
@admin_required
def add_process_asset(process_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO process_assets (process_id, asset_id, role_in_process) VALUES (?, ?, ?)', (
                process_id, int(request.form['asset_id']), request.form.get('role_in_process')
            ))
            conn.commit()
            flash('Актив привязан к процессу!')
        except sqlite3.IntegrityError:
            flash('Этот актив уже привязан к процессу.')
    return redirect(url_for('process_detail', id=process_id))

@app.route('/process_assets/delete/<int:id>', methods=['POST'])
@admin_required
def delete_process_asset(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT process_id FROM process_assets WHERE id = ?', (id,))
        row = cursor.fetchone()
        if row:
            cursor.execute('DELETE FROM process_assets WHERE id = ?', (id,))
            conn.commit()
            flash('Связь процесса с активом удалена!')
            return redirect(url_for('process_detail', id=row[0]))
    return redirect(url_for('list_processes'))

@app.route('/subprocesses/add', methods=['GET', 'POST'])
@admin_required
def add_subprocess():
    process_id = request.args.get('process_id') or request.form.get('process_id')
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM processes ORDER BY name')
        processes = cursor.fetchall()
        if request.method == 'POST':
            cursor.execute('''
                INSERT INTO subprocesses (process_id, name, description, input_data, output_data, responsible_person, used_systems, order_index)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                int(request.form['process_id']), request.form['name'], request.form.get('description'),
                request.form.get('input_data'), request.form.get('output_data'), request.form.get('responsible_person'),
                request.form.get('used_systems'), request.form.get('order_index') or None
            ))
            conn.commit()
            flash('Подпроцесс создан!')
            return redirect(url_for('process_detail', id=int(request.form['process_id'])))
    return render_template('subprocess_form.html', subprocess=None, processes=processes, selected_process_id=int(process_id) if process_id else None)

@app.route('/subprocesses/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_subprocess(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, process_id, name, description, input_data, output_data, responsible_person, used_systems, order_index FROM subprocesses WHERE id = ?', (id,))
        subprocess = cursor.fetchone()
        if not subprocess:
            flash('Подпроцесс не найден!')
            return redirect(url_for('list_processes'))
        cursor.execute('SELECT id, name FROM processes ORDER BY name')
        processes = cursor.fetchall()
        if request.method == 'POST':
            cursor.execute('''
                UPDATE subprocesses
                SET process_id = ?, name = ?, description = ?, input_data = ?, output_data = ?, responsible_person = ?, used_systems = ?, order_index = ?
                WHERE id = ?
            ''', (
                int(request.form['process_id']), request.form['name'], request.form.get('description'),
                request.form.get('input_data'), request.form.get('output_data'), request.form.get('responsible_person'),
                request.form.get('used_systems'), request.form.get('order_index') or None, id
            ))
            conn.commit()
            flash('Подпроцесс обновлен!')
            return redirect(url_for('process_detail', id=int(request.form['process_id'])))
    return render_template('subprocess_form.html', subprocess=subprocess, processes=processes, selected_process_id=None)

@app.route('/subprocesses/delete/<int:id>', methods=['POST'])
@admin_required
def delete_subprocess(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT process_id FROM subprocesses WHERE id = ?', (id,))
        row = cursor.fetchone()
        if not row:
            return redirect(url_for('list_processes'))
        cursor.execute('SELECT COUNT(*) FROM process_risks WHERE subprocess_id = ?', (id,))
        if cursor.fetchone()[0] > 0:
            flash('Нельзя удалить подпроцесс, у которого есть риски!')
            return redirect(url_for('process_detail', id=row[0]))
        cursor.execute('DELETE FROM subprocesses WHERE id = ?', (id,))
        conn.commit()
    flash('Подпроцесс удален!')
    return redirect(url_for('process_detail', id=row[0]))

@app.route('/processes/<int:process_id>/bpmn', methods=['GET', 'POST'])
@admin_required
def edit_process_bpmn(process_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name FROM processes WHERE id = ?', (process_id,))
        process = cursor.fetchone()
        if not process:
            flash('Процесс не найден!')
            return redirect(url_for('list_processes'))
        if request.method == 'POST':
            bpmn_json = request.form.get('bpmn_json')
            cursor.execute('DELETE FROM process_bpmn WHERE process_id = ?', (process_id,))
            cursor.execute('INSERT INTO process_bpmn (process_id, bpmn_json) VALUES (?, ?)', (process_id, bpmn_json))
            conn.commit()
            flash('BPMN-модель сохранена!')
            return redirect(url_for('process_detail', id=process_id))
        cursor.execute('SELECT id, name FROM subprocesses WHERE process_id = ? ORDER BY COALESCE(order_index, 9999), id', (process_id,))
        subprocesses = cursor.fetchall()
        bpmn_subprocess_risks = get_bpmn_subprocess_risk_summary(cursor, process_id)
        cursor.execute('SELECT id, bpmn_json FROM process_bpmn WHERE process_id = ? ORDER BY id DESC LIMIT 1', (process_id,))
        bpmn = cursor.fetchone()
        bpmn_model = enrich_bpmn_model_with_risks(parse_bpmn_json(bpmn[1] if bpmn else None), bpmn_subprocess_risks)
        bpmn_business_context = build_bpmn_business_context(cursor, process_id, bpmn_model)
    bpmn_critical_path = build_bpmn_critical_path(bpmn_model)
    return render_template('process_bpmn_form.html', process=process, bpmn=bpmn, bpmn_model=bpmn_model, subprocesses=subprocesses, bpmn_subprocess_risks=bpmn_subprocess_risks, bpmn_business_context=bpmn_business_context, bpmn_critical_path=bpmn_critical_path)

@app.route('/api/process_bpmn/<int:process_id>', methods=['GET'])
@login_required
def api_get_process_bpmn(process_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT bpmn_json FROM process_bpmn WHERE process_id = ? ORDER BY id DESC LIMIT 1', (process_id,))
        row = cursor.fetchone()
    if not row or not row[0]:
        return jsonify({'process_id': process_id, 'bpmn': {'nodes': [], 'edges': []}})
    try:
        return jsonify({'process_id': process_id, 'bpmn': json.loads(row[0])})
    except json.JSONDecodeError:
        return jsonify({'process_id': process_id, 'bpmn_raw': row[0], 'error': 'Invalid BPMN JSON'}), 422

@app.route('/api/process_bpmn/<int:process_id>', methods=['POST'])
@admin_required
def api_save_process_bpmn(process_id):
    payload = request.get_json(silent=True) or {}
    bpmn = payload.get('bpmn', payload)
    if not isinstance(bpmn, dict) or 'nodes' not in bpmn or 'edges' not in bpmn:
        return jsonify({'success': False, 'error': 'Expected BPMN JSON with nodes and edges'}), 400
    bpmn_json = json.dumps(bpmn, ensure_ascii=False)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM processes WHERE id = ?', (process_id,))
        if not cursor.fetchone():
            return jsonify({'success': False, 'error': 'Process not found'}), 404
        cursor.execute('DELETE FROM process_bpmn WHERE process_id = ?', (process_id,))
        cursor.execute('INSERT INTO process_bpmn (process_id, bpmn_json) VALUES (?, ?)', (process_id, bpmn_json))
        conn.commit()
    return jsonify({'success': True, 'process_id': process_id, 'bpmn': bpmn})

def get_asset_value(cursor, asset_id):
    if not asset_id:
        return 1
    cursor.execute('''
        SELECT life_health, economy, ecology, dependency, social, international
        FROM assets
        WHERE id = ?
    ''', (asset_id,))
    row = cursor.fetchone()
    if not row:
        return 1
    values = [value for value in row if value is not None]
    return sum(values) / len(values) if values else 1

def calculate_process_risk_from_form(form, cursor=None):
    probability = float(form.get('probability') or 0)
    vulnerability_level = float(form.get('vulnerability_level') or 1)
    impact = float(form.get('impact') or 0)
    control_effectiveness = float(form.get('control_effectiveness') or 0)
    cost = float(form.get('cost') or 0)
    asset_id = form.get('asset_id') or None
    asset_value = get_asset_value(cursor, asset_id) if cursor else 1
    metrics = calculate_process_risk_metrics(probability, vulnerability_level, impact, control_effectiveness, cost, asset_value)
    risk_category = classify_numeric_risk(metrics['residual_risk'])
    return {
        'probability': probability,
        'vulnerability_level': vulnerability_level,
        'impact': impact,
        'initial_risk': metrics['risk_level'],
        'control_effectiveness': control_effectiveness,
        'residual_risk': metrics['residual_risk'],
        'risk_level': metrics['risk_level'],
        'risk_category': risk_category,
        'cost': cost,
        'risk_reduction': metrics['risk_reduction'],
        'priority': metrics['priority'],
    }

def get_process_risk_filters():
    return {
        'process_id': request.args.get('process_id', ''),
        'risk_level': request.args.get('risk_level', ''),
        'priority': request.args.get('priority', ''),
        'status': request.args.get('status', ''),
        'confidence': request.args.get('confidence', ''),
        'owner': request.args.get('owner', '').strip(),
        'overdue': request.args.get('overdue', ''),
    }

def build_process_risk_where(filters):
    where = []
    params = []
    if filters['process_id']:
        where.append('pr.process_id = ?')
        params.append(filters['process_id'])
    if filters['risk_level']:
        where.append('COALESCE(pr.risk_category, pr.risk_level) = ?')
        params.append(filters['risk_level'])
    if filters['priority']:
        where.append('pr.priority = ?')
        params.append(filters['priority'])
    if filters['status']:
        where.append("COALESCE(pr.status, 'Draft') = ?")
        params.append(filters['status'])
    if filters['confidence']:
        where.append("COALESCE(pr.confidence, 'Medium') = ?")
        params.append(filters['confidence'])
    if filters['owner']:
        where.append('(pr.risk_owner LIKE ? OR pr.mitigation_owner LIKE ?)')
        params.extend([f"%{filters['owner']}%", f"%{filters['owner']}%"])
    if filters['overdue']:
        where.append("pr.due_date IS NOT NULL AND pr.due_date <> '' AND pr.due_date < DATE('now') AND COALESCE(pr.status, '') NOT IN ('Closed')")
    append_process_risk_visibility_filter(where, params, 'p', 'pr')

    return f"WHERE {' AND '.join(where)}" if where else '', params

def fetch_process_risk_register(cursor, filters):
    where_sql, params = build_process_risk_where(filters)
    cursor.execute(f'''
        SELECT pr.id, p.name, sp.name, a.name, pr.probability, pr.impact, pr.initial_risk,
               pr.control_effectiveness, pr.residual_risk, COALESCE(pr.risk_category, pr.risk_level), pr.ai_recommendation,
               pr.vulnerability_level, pr.cost, pr.risk_reduction, pr.priority,
               COALESCE(pr.status, 'Draft'), pr.risk_owner, pr.mitigation_owner, pr.due_date,
               COALESCE(pr.assessment_source, 'Expert'), COALESCE(pr.confidence, 'Medium'), pr.evidence,
               pr.last_reviewed_at, pr.risk_description, t.name, v.name, cm.name,
               pr.risk_owner_user_id, pr.mitigation_owner_user_id, p.owner_user_id
        FROM process_risks pr
        JOIN processes p ON p.id = pr.process_id
        LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
        LEFT JOIN assets a ON a.id = pr.asset_id
        LEFT JOIN threats t ON t.id = pr.threat_id
        LEFT JOIN vulnerabilities v ON v.id = pr.vulnerability_id
        LEFT JOIN control_measures cm ON cm.id = pr.control_measure_id
        {where_sql}
        ORDER BY pr.residual_risk DESC
    ''', params)
    return cursor.fetchall()

def empty_process_risk_filters():
    return {
        'process_id': '',
        'risk_level': '',
        'priority': '',
        'status': '',
        'confidence': '',
        'owner': '',
        'overdue': '',
    }

def load_user_options(cursor):
    cursor.execute('''
        SELECT id, username, role
        FROM users
        ORDER BY
            CASE role
                WHEN 'process_owner' THEN 1
                WHEN 'risk_manager' THEN 2
                WHEN 'expert' THEN 3
                WHEN 'auditor' THEN 4
                WHEN 'admin' THEN 5
                ELSE 9
            END,
            username
    ''')
    return cursor.fetchall()

def get_user_display(cursor, user_id):
    if not user_id:
        return ''
    cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    return row[0] if row else ''

def load_user_task_queue(role=None, username=None, expert_id=None):
    role = role or (session.get('role') if has_request_context() else None)
    username = username or (session.get('username') if has_request_context() else None)
    expert_id = expert_id if expert_id is not None else (session.get('expert_id') if has_request_context() else None)
    role = role or ''
    username = username or ''
    current_user_id = session.get('user_id') if has_request_context() else None

    with get_db_connection() as conn:
        cursor = conn.cursor()
        risks = fetch_process_risk_register(cursor, empty_process_risk_filters())

        workflow_tasks = []
        for risk in risks:
            assigned_user_ids = {risk[27], risk[28], risk[29]}
            if role == 'process_owner' and current_user_id not in assigned_user_ids:
                continue
            if role == 'expert' and risk[27] != current_user_id:
                continue
            actions = get_available_workflow_actions(risk[15], role)
            if actions:
                workflow_tasks.append({'risk': risk, 'actions': actions})

        treatment_where = []
        treatment_params = []
        if role not in ('admin', 'risk_manager', 'auditor'):
            treatment_where.append('(rta.owner_user_id = ? OR pr.risk_owner_user_id = ? OR pr.mitigation_owner_user_id = ? OR rta.owner LIKE ? OR pr.risk_owner LIKE ? OR pr.mitigation_owner LIKE ?)')
            treatment_params.extend([current_user_id, current_user_id, current_user_id, f"%{username}%", f"%{username}%", f"%{username}%"])
        treatment_where_sql = f"AND {' AND '.join(treatment_where)}" if treatment_where else ''
        cursor.execute(f'''
            SELECT rta.id, rta.title, p.name, sp.name, rta.owner, rta.due_date, rta.progress,
                   COALESCE(rta.status, 'Planned'), pr.residual_risk, pr.id,
                   CASE WHEN rta.due_date IS NOT NULL AND rta.due_date <> '' AND rta.due_date < DATE('now')
                        AND COALESCE(rta.status, '') NOT IN ('Completed', 'Accepted', 'Cancelled')
                        THEN 1 ELSE 0 END AS is_overdue
            FROM risk_treatment_actions rta
            JOIN process_risks pr ON pr.id = rta.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            WHERE COALESCE(rta.status, '') NOT IN ('Completed', 'Accepted', 'Cancelled')
            {treatment_where_sql}
            ORDER BY is_overdue DESC,
                     CASE WHEN rta.due_date IS NULL OR rta.due_date = '' THEN 1 ELSE 0 END,
                     rta.due_date ASC,
                     pr.residual_risk DESC
            LIMIT 50
        ''', treatment_params)
        treatment_tasks = cursor.fetchall()

        expert_tasks = []
        if role == 'expert' and expert_id:
            cursor.execute('''
                SELECT pr.id, p.name, sp.name, pr.risk_description, pr.residual_risk,
                       COALESCE(pr.risk_category, pr.risk_level), COALESCE(pr.status, 'Draft')
                FROM process_risks pr
                JOIN processes p ON p.id = pr.process_id
                LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
                LEFT JOIN process_risk_expert_assessments prea
                    ON prea.process_risk_id = pr.id AND prea.expert_id = ?
                WHERE prea.id IS NULL
                  AND COALESCE(pr.status, '') NOT IN ('Closed')
                ORDER BY pr.residual_risk DESC
                LIMIT 50
            ''', (expert_id,))
            expert_tasks = cursor.fetchall()

    return {
        'workflow_tasks': workflow_tasks,
        'treatment_tasks': treatment_tasks,
        'expert_tasks': expert_tasks,
        'summary': {
            'workflow': len(workflow_tasks),
            'treatments': len(treatment_tasks),
            'overdue_treatments': sum(1 for item in treatment_tasks if item[10]),
            'expert': len(expert_tasks),
        },
    }

def load_treatment_risk_options(cursor):
    cursor.execute('''
        SELECT pr.id, p.name, sp.name, pr.risk_description, COALESCE(pr.risk_category, pr.risk_level), pr.residual_risk
        FROM process_risks pr
        JOIN processes p ON p.id = pr.process_id
        LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
        ORDER BY p.name, sp.name, pr.residual_risk DESC
    ''')
    return cursor.fetchall()

def load_dashboard_data():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM companies')
        company_count = (cursor.fetchone() or (0,))[0]
        cursor.execute('SELECT COUNT(*) FROM processes')
        process_count = (cursor.fetchone() or (0,))[0]
        cursor.execute('''
            SELECT
                COUNT(*),
                SUM(CASE WHEN COALESCE(risk_category, risk_level) = 'Высокий' THEN 1 ELSE 0 END),
                SUM(CASE WHEN COALESCE(risk_category, risk_level) = 'Средний' THEN 1 ELSE 0 END),
                SUM(CASE WHEN COALESCE(risk_category, risk_level) = 'Низкий' THEN 1 ELSE 0 END),
                SUM(CASE WHEN due_date IS NOT NULL AND due_date <> '' AND due_date < DATE('now')
                    AND COALESCE(status, '') NOT IN ('Closed') THEN 1 ELSE 0 END),
                SUM(CASE WHEN COALESCE(status, '') IN ('Closed') THEN 1 ELSE 0 END)
            FROM process_risks
        ''')
        summary = cursor.fetchone()
        cursor.execute('''
            SELECT COALESCE(status, 'Draft'), COUNT(*)
            FROM process_risks
            GROUP BY COALESCE(status, 'Draft')
            ORDER BY COUNT(*) DESC
        ''')
        status_counts = cursor.fetchall()
        cursor.execute('''
            SELECT p.id, p.name, COUNT(pr.id), COALESCE(MAX(pr.residual_risk), 0),
                   SUM(CASE WHEN COALESCE(pr.risk_category, pr.risk_level) = 'Высокий' THEN 1 ELSE 0 END)
            FROM processes p
            LEFT JOIN process_risks pr ON pr.process_id = p.id
            GROUP BY p.id, p.name
            ORDER BY COALESCE(MAX(pr.residual_risk), 0) DESC, COUNT(pr.id) DESC
            LIMIT 8
        ''')
        process_ranking = cursor.fetchall()
        cursor.execute('''
            SELECT pr.id, p.name, sp.name, pr.risk_description, COALESCE(pr.risk_category, pr.risk_level),
                   pr.residual_risk, COALESCE(pr.status, 'Draft'), pr.risk_owner, pr.due_date
            FROM process_risks pr
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            ORDER BY pr.residual_risk DESC
            LIMIT 10
        ''')
        top_risks = cursor.fetchall()
        cursor.execute('''
            SELECT
                COUNT(*),
                SUM(CASE WHEN COALESCE(status, '') = 'In progress' THEN 1 ELSE 0 END),
                SUM(CASE WHEN COALESCE(status, '') = 'Waiting validation' THEN 1 ELSE 0 END),
                SUM(CASE WHEN COALESCE(status, '') IN ('Completed', 'Accepted') THEN 1 ELSE 0 END),
                SUM(CASE WHEN due_date IS NOT NULL AND due_date <> '' AND due_date < DATE('now')
                    AND COALESCE(status, '') NOT IN ('Completed', 'Accepted', 'Cancelled') THEN 1 ELSE 0 END),
                COALESCE(AVG(progress), 0)
            FROM risk_treatment_actions
        ''')
        treatment_summary = cursor.fetchone()
        cursor.execute('''
            SELECT COALESCE(status, 'Planned'), COUNT(*), COALESCE(AVG(progress), 0)
            FROM risk_treatment_actions
            GROUP BY COALESCE(status, 'Planned')
            ORDER BY COUNT(*) DESC
        ''')
        treatment_status_counts = cursor.fetchall()
        cursor.execute('''
            SELECT rta.id, rta.title, p.name, sp.name, rta.owner, rta.due_date, rta.progress,
                   COALESCE(rta.status, 'Planned'), pr.residual_risk
            FROM risk_treatment_actions rta
            JOIN process_risks pr ON pr.id = rta.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            WHERE COALESCE(rta.status, '') NOT IN ('Completed', 'Accepted', 'Cancelled')
            ORDER BY
                CASE WHEN rta.due_date IS NULL OR rta.due_date = '' THEN 1 ELSE 0 END,
                rta.due_date ASC,
                pr.residual_risk DESC
            LIMIT 8
        ''')
        upcoming_treatments = cursor.fetchall()
        cursor.execute('''
            SELECT rta.id, rta.title, p.name, rta.owner, rta.due_date, rta.progress, pr.residual_risk
            FROM risk_treatment_actions rta
            JOIN process_risks pr ON pr.id = rta.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            WHERE COALESCE(rta.status, '') = 'Waiting validation'
            ORDER BY pr.residual_risk DESC
            LIMIT 8
        ''')
        validation_treatments = cursor.fetchall()
    tasks = load_user_task_queue()
    return {
        'company_count': company_count,
        'process_count': process_count,
        'summary': summary,
        'status_counts': status_counts,
        'process_ranking': process_ranking,
        'top_risks': top_risks,
        'treatment_summary': treatment_summary,
        'treatment_status_counts': treatment_status_counts,
        'upcoming_treatments': upcoming_treatments,
        'validation_treatments': validation_treatments,
        'tasks': tasks,
    }

def load_operational_analytics():
    with get_db_connection() as conn:
        cursor = conn.cursor()

        risk_where = []
        risk_params = []
        append_process_risk_visibility_filter(risk_where, risk_params, 'p', 'pr')
        risk_where_sql = f"WHERE {' AND '.join(risk_where)}" if risk_where else ''

        cursor.execute(f'''
            SELECT
                COUNT(*),
                SUM(CASE WHEN COALESCE(pr.risk_category, pr.risk_level) = 'Высокий' THEN 1 ELSE 0 END),
                SUM(CASE WHEN pr.due_date IS NOT NULL AND pr.due_date <> '' AND pr.due_date < DATE('now')
                    AND COALESCE(pr.status, '') NOT IN ('Closed') THEN 1 ELSE 0 END),
                SUM(CASE WHEN pr.last_reviewed_at IS NULL OR pr.last_reviewed_at = ''
                    OR pr.last_reviewed_at < DATE('now', '-30 day') THEN 1 ELSE 0 END),
                COALESCE(AVG(pr.residual_risk), 0),
                COALESCE(MAX(pr.residual_risk), 0)
            FROM process_risks pr
            JOIN processes p ON p.id = pr.process_id
            {risk_where_sql}
        ''', risk_params)
        risk_kpis = cursor.fetchone()

        cursor.execute(f'''
            SELECT COALESCE(pr.status, 'Draft'), COUNT(*),
                   COALESCE(AVG(JULIANDAY('now') - JULIANDAY(COALESCE(pr.last_reviewed_at, DATE('now')))), 0),
                   MAX(JULIANDAY('now') - JULIANDAY(COALESCE(pr.last_reviewed_at, DATE('now'))))
            FROM process_risks pr
            JOIN processes p ON p.id = pr.process_id
            {risk_where_sql}
            GROUP BY COALESCE(pr.status, 'Draft')
            ORDER BY COUNT(*) DESC
        ''', risk_params)
        risk_status_aging = cursor.fetchall()

        cursor.execute(f'''
            SELECT pr.id, p.name, sp.name, pr.risk_description, COALESCE(pr.status, 'Draft'),
                   COALESCE(pr.risk_category, pr.risk_level), pr.residual_risk, pr.due_date,
                   CAST(JULIANDAY('now') - JULIANDAY(pr.due_date) AS INTEGER) AS overdue_days
            FROM process_risks pr
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            {risk_where_sql}
              {'AND' if risk_where_sql else 'WHERE'} pr.due_date IS NOT NULL AND pr.due_date <> ''
              AND pr.due_date < DATE('now')
              AND COALESCE(pr.status, '') NOT IN ('Closed')
            ORDER BY overdue_days DESC, pr.residual_risk DESC
            LIMIT 15
        ''', risk_params)
        overdue_risks = cursor.fetchall()

        cursor.execute(f'''
            SELECT p.id, p.name,
                   COUNT(pr.id) AS total_risks,
                   SUM(CASE WHEN COALESCE(pr.risk_category, pr.risk_level) = 'Высокий' THEN 1 ELSE 0 END) AS high_risks,
                   COALESCE(AVG(pr.residual_risk), 0) AS avg_residual,
                   COALESCE(MAX(pr.residual_risk), 0) AS max_residual
            FROM processes p
            LEFT JOIN process_risks pr ON pr.process_id = p.id
            {'WHERE ' + ' AND '.join(risk_where).replace('pr.', 'pr.').replace('p.', 'p.') if risk_where else ''}
            GROUP BY p.id, p.name
            HAVING COUNT(pr.id) > 0
            ORDER BY max_residual DESC, high_risks DESC
        ''', risk_params)
        process_risk_heatmap = cursor.fetchall()

        treatment_where = []
        treatment_params = []
        append_treatment_visibility_filter(treatment_where, treatment_params, 'p', 'pr', 'rta')
        treatment_where_sql = f"WHERE {' AND '.join(treatment_where)}" if treatment_where else ''

        cursor.execute(f'''
            SELECT
                COUNT(*),
                SUM(CASE WHEN rta.due_date IS NOT NULL AND rta.due_date <> '' AND rta.due_date < DATE('now')
                    AND COALESCE(rta.status, '') NOT IN ('Completed', 'Accepted', 'Cancelled') THEN 1 ELSE 0 END),
                COALESCE(AVG(rta.progress), 0),
                COALESCE(AVG(CASE WHEN rta.expected_residual_risk IS NOT NULL AND rta.actual_residual_risk IS NOT NULL
                    THEN rta.expected_residual_risk - rta.actual_residual_risk END), 0),
                SUM(CASE WHEN rta.actual_residual_risk IS NOT NULL AND rta.expected_residual_risk IS NOT NULL
                    AND rta.actual_residual_risk <= rta.expected_residual_risk THEN 1 ELSE 0 END)
            FROM risk_treatment_actions rta
            JOIN process_risks pr ON pr.id = rta.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            {treatment_where_sql}
        ''', treatment_params)
        treatment_kpis = cursor.fetchone()

        cursor.execute(f'''
            SELECT COALESCE(rta.status, 'Planned'), COUNT(*), COALESCE(AVG(rta.progress), 0)
            FROM risk_treatment_actions rta
            JOIN process_risks pr ON pr.id = rta.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            {treatment_where_sql}
            GROUP BY COALESCE(rta.status, 'Planned')
            ORDER BY COUNT(*) DESC
        ''', treatment_params)
        treatment_statuses = cursor.fetchall()

        cursor.execute(f'''
            SELECT rta.id, rta.title, p.name, pr.risk_description, rta.owner, rta.due_date,
                   rta.progress, COALESCE(rta.status, 'Planned'), pr.residual_risk,
                   CAST(JULIANDAY('now') - JULIANDAY(rta.due_date) AS INTEGER) AS overdue_days
            FROM risk_treatment_actions rta
            JOIN process_risks pr ON pr.id = rta.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            {treatment_where_sql}
              {'AND' if treatment_where_sql else 'WHERE'} rta.due_date IS NOT NULL AND rta.due_date <> ''
              AND rta.due_date < DATE('now')
              AND COALESCE(rta.status, '') NOT IN ('Completed', 'Accepted', 'Cancelled')
            ORDER BY overdue_days DESC, pr.residual_risk DESC
            LIMIT 15
        ''', treatment_params)
        overdue_treatments = cursor.fetchall()

        cursor.execute(f'''
            SELECT rta.id, rta.title, p.name, rta.expected_residual_risk, rta.actual_residual_risk,
                   (rta.expected_residual_risk - rta.actual_residual_risk) AS delta,
                   COALESCE(rta.status, 'Planned')
            FROM risk_treatment_actions rta
            JOIN process_risks pr ON pr.id = rta.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            {treatment_where_sql}
              {'AND' if treatment_where_sql else 'WHERE'} rta.expected_residual_risk IS NOT NULL
              AND rta.actual_residual_risk IS NOT NULL
            ORDER BY delta ASC
            LIMIT 15
        ''', treatment_params)
        treatment_effectiveness = cursor.fetchall()

        cursor.execute('''
            SELECT AVG(JULIANDAY(approved.created_at) - JULIANDAY(submitted.created_at))
            FROM process_risk_workflow submitted
            JOIN process_risk_workflow approved ON approved.process_risk_id = submitted.process_risk_id
            WHERE submitted.to_status = 'In Review'
              AND approved.to_status = 'Approved'
              AND approved.created_at > submitted.created_at
        ''')
        avg_approval_days = cursor.fetchone()[0]

    return {
        'risk_kpis': risk_kpis,
        'risk_status_aging': risk_status_aging,
        'overdue_risks': overdue_risks,
        'process_risk_heatmap': process_risk_heatmap,
        'treatment_kpis': treatment_kpis,
        'treatment_statuses': treatment_statuses,
        'overdue_treatments': overdue_treatments,
        'treatment_effectiveness': treatment_effectiveness,
        'avg_approval_days': avg_approval_days,
    }

def compliance_status_weight(status):
    return {
        'Not assessed': 0,
        'Gap': 1,
        'Partially implemented': 2,
        'Implemented': 3,
        'Verified': 4,
    }.get(status or 'Not assessed', 0)

def infer_compliance_status(treatment_status, progress):
    if treatment_status in ('Completed', 'Accepted'):
        return 'Verified'
    if treatment_status == 'In progress' or (progress or 0) >= 50:
        return 'Partially implemented'
    if treatment_status == 'Planned':
        return 'Gap'
    return 'Not assessed'

def sync_compliance_evidence(cursor):
    domain_keywords = [
        ('Identity and Access', ['RBAC', 'IAM', 'сертификат', 'сертификаты', 'auth', 'доступ', 'Access', 'Logical access']),
        ('Cryptography', ['TLS', 'crypt', 'ключ', 'шифр']),
        ('Network', ['NAC', 'VLAN', 'firewall', 'сегментац', 'MQTT', 'API', 'Network']),
        ('Monitoring', ['monitoring', 'SIEM', 'heartbeat', 'alert', 'лог', 'Monitoring']),
        ('Asset Management', ['registry', 'inventory', 'GIS', 'инвентар']),
        ('Device Hardening', ['hardening', 'secure boot', 'baseline', 'configuration']),
        ('Firmware Security', ['firmware', 'прошив']),
    ]
    cursor.execute('''
        SELECT rta.id, rta.title, rta.status, rta.progress, rta.evidence, rta.owner_user_id
        FROM risk_treatment_actions rta
    ''')
    treatments = cursor.fetchall()
    for treatment_id, title, status, progress, evidence, owner_user_id in treatments:
        text = f"{title or ''} {evidence or ''}".lower()
        domains = {
            domain
            for domain, keywords in domain_keywords
            if any(keyword.lower() in text for keyword in keywords)
        }
        if not domains:
            continue
        placeholders = ','.join('?' for _ in domains)
        cursor.execute(f'''
            SELECT id
            FROM compliance_requirements
            WHERE domain IN ({placeholders})
        ''', tuple(domains))
        requirement_ids = [row[0] for row in cursor.fetchall()]
        for requirement_id in requirement_ids:
            cursor.execute('''
                SELECT id, status
                FROM compliance_evidence
                WHERE requirement_id = ? AND treatment_id = ?
            ''', (requirement_id, treatment_id))
            existing = cursor.fetchone()
            inferred_status = infer_compliance_status(status, progress)
            if existing:
                if compliance_status_weight(inferred_status) > compliance_status_weight(existing[1]):
                    cursor.execute('''
                        UPDATE compliance_evidence
                        SET status = ?, owner_user_id = COALESCE(owner_user_id, ?), updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (inferred_status, owner_user_id, existing[0]))
            else:
                cursor.execute('''
                    INSERT INTO compliance_evidence (requirement_id, treatment_id, status, evidence, owner_user_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    requirement_id,
                    treatment_id,
                    inferred_status,
                    evidence or 'Автоматически связано с мерой обработки риска.',
                    owner_user_id,
                ))

def load_compliance_dashboard():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        sync_compliance_evidence(cursor)
        conn.commit()

        visibility_where = []
        visibility_params = []
        append_treatment_visibility_filter(visibility_where, visibility_params, 'p', 'pr', 'rta')
        visibility_sql = f"AND {' AND '.join(visibility_where)}" if visibility_where else ''

        cursor.execute(f'''
            SELECT s.id, s.name, s.version,
                   COUNT(DISTINCT r.id) AS requirements_total,
                   COUNT(DISTINCT ce.requirement_id) AS requirements_linked,
                   SUM(CASE WHEN ce.status = 'Verified' THEN 1 ELSE 0 END) AS verified,
                   SUM(CASE WHEN ce.status = 'Implemented' THEN 1 ELSE 0 END) AS implemented,
                   SUM(CASE WHEN ce.status = 'Partially implemented' THEN 1 ELSE 0 END) AS partial,
                   SUM(CASE WHEN ce.status = 'Gap' THEN 1 ELSE 0 END) AS gaps
            FROM compliance_standards s
            JOIN compliance_requirements r ON r.standard_id = s.id
            LEFT JOIN compliance_evidence ce ON ce.requirement_id = r.id
            LEFT JOIN risk_treatment_actions rta ON rta.id = ce.treatment_id
            LEFT JOIN process_risks pr ON pr.id = rta.process_risk_id
            LEFT JOIN processes p ON p.id = pr.process_id
            WHERE ce.id IS NULL OR 1=1
            {visibility_sql}
            GROUP BY s.id, s.name, s.version
            ORDER BY s.name
        ''', visibility_params)
        standards = cursor.fetchall()

        cursor.execute(f'''
            SELECT r.id, s.name, s.version, r.code, r.title, r.domain,
                   COALESCE(MAX(CASE ce.status
                        WHEN 'Verified' THEN 4
                        WHEN 'Implemented' THEN 3
                        WHEN 'Partially implemented' THEN 2
                        WHEN 'Gap' THEN 1
                        ELSE 0 END), 0) AS status_weight,
                   COUNT(ce.id) AS evidence_count
            FROM compliance_requirements r
            JOIN compliance_standards s ON s.id = r.standard_id
            LEFT JOIN compliance_evidence ce ON ce.requirement_id = r.id
            LEFT JOIN risk_treatment_actions rta ON rta.id = ce.treatment_id
            LEFT JOIN process_risks pr ON pr.id = rta.process_risk_id
            LEFT JOIN processes p ON p.id = pr.process_id
            WHERE ce.id IS NULL OR 1=1
            {visibility_sql}
            GROUP BY r.id, s.name, s.version, r.code, r.title, r.domain
            ORDER BY s.name, r.code
        ''', visibility_params)
        requirements = cursor.fetchall()

        cursor.execute(f'''
            SELECT ce.id, s.name, r.code, r.title, r.domain, ce.status, ce.evidence,
                   rta.title, p.name, pr.risk_description, ce.updated_at
            FROM compliance_evidence ce
            JOIN compliance_requirements r ON r.id = ce.requirement_id
            JOIN compliance_standards s ON s.id = r.standard_id
            LEFT JOIN risk_treatment_actions rta ON rta.id = ce.treatment_id
            LEFT JOIN process_risks pr ON pr.id = rta.process_risk_id
            LEFT JOIN processes p ON p.id = pr.process_id
            WHERE 1=1
            {visibility_sql}
            ORDER BY s.name, r.code, ce.updated_at DESC
        ''', visibility_params)
        evidence = cursor.fetchall()

    status_labels = {
        0: 'Not assessed',
        1: 'Gap',
        2: 'Partially implemented',
        3: 'Implemented',
        4: 'Verified',
    }
    summary = {
        'requirements': len(requirements),
        'gaps': sum(1 for row in requirements if row[6] <= 1),
        'partial': sum(1 for row in requirements if row[6] == 2),
        'implemented': sum(1 for row in requirements if row[6] >= 3),
        'evidence': len(evidence),
    }
    return {
        'standards': standards,
        'requirements': requirements,
        'evidence': evidence,
        'summary': summary,
        'status_labels': status_labels,
    }

def make_quality_item(title, detail='', url=None, meta=''):
    return {
        'title': title,
        'detail': detail,
        'url': url,
        'meta': meta,
    }

def safe_report_filename(value):
    cleaned = re.sub(r'[^A-Za-z0-9А-Яа-я_-]+', '_', value or 'report').strip('_')
    return cleaned[:80] or 'report'

def add_csv_to_zip(zip_file, filename, headers, rows):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    zip_file.writestr(filename, '\ufeff' + output.getvalue())

def build_company_report_package(company_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, industry, description, created_at FROM companies WHERE id = ?', (company_id,))
        company = cursor.fetchone()
        if not company:
            return None

        cursor.execute('''
            SELECT id, name, process_type, owner, input_data, output_data, regulations, resources, description, created_at
            FROM processes
            WHERE company_id = ?
            ORDER BY name
        ''', (company_id,))
        processes = cursor.fetchall()

        cursor.execute('''
            SELECT p.name, sp.name, sp.responsible_person, sp.used_systems, sp.input_data, sp.output_data, sp.description
            FROM subprocesses sp
            JOIN processes p ON p.id = sp.process_id
            WHERE p.company_id = ?
            ORDER BY p.name, COALESCE(sp.order_index, 9999), sp.id
        ''', (company_id,))
        subprocesses = cursor.fetchall()

        cursor.execute('''
            SELECT p.name, sp.name, a.name, pa.role_in_process,
                   a.life_health, a.economy, a.ecology, a.dependency, a.social, a.international,
                   a.threat_probability,
                   COUNT(DISTINCT ae.id), COUNT(DISTINCT tp.id)
            FROM processes p
            LEFT JOIN subprocesses sp ON sp.process_id = p.id
            JOIN process_assets pa ON pa.process_id = p.id
            JOIN assets a ON a.id = pa.asset_id
            LEFT JOIN asset_evaluations ae ON ae.asset_id = a.id
            LEFT JOIN threat_probabilities tp ON tp.asset_id = a.id
            WHERE p.company_id = ?
            GROUP BY p.name, sp.name, a.id, pa.role_in_process
            ORDER BY p.name, a.name
        ''', (company_id,))
        assets = cursor.fetchall()

        cursor.execute('''
            SELECT pr.id, p.name, sp.name, a.name, t.name, v.name, v.category, cm.name,
                   pr.risk_description, pr.probability, pr.vulnerability_level, pr.impact,
                   pr.initial_risk, pr.control_effectiveness, pr.residual_risk,
                   COALESCE(pr.risk_category, pr.risk_level), pr.priority,
                   pr.status, pr.risk_owner, pr.mitigation_owner, pr.due_date,
                   pr.assessment_source, pr.confidence, pr.evidence, pr.last_reviewed_at,
                   pr.ai_recommendation
            FROM process_risks pr
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            LEFT JOIN assets a ON a.id = pr.asset_id
            LEFT JOIN threats t ON t.id = pr.threat_id
            LEFT JOIN vulnerabilities v ON v.id = pr.vulnerability_id
            LEFT JOIN control_measures cm ON cm.id = pr.control_measure_id
            WHERE p.company_id = ?
            ORDER BY pr.residual_risk DESC
        ''', (company_id,))
        risks = cursor.fetchall()

        cursor.execute('''
            SELECT rta.id, p.name, sp.name, pr.risk_description, COALESCE(pr.risk_category, pr.risk_level),
                   pr.residual_risk, rta.title, rta.treatment_type, rta.owner, rta.due_date,
                   rta.cost, rta.expected_residual_risk, rta.actual_residual_risk,
                   rta.progress, rta.status, rta.evidence
            FROM risk_treatment_actions rta
            JOIN process_risks pr ON pr.id = rta.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            WHERE p.company_id = ?
            ORDER BY
                CASE WHEN rta.due_date IS NULL OR rta.due_date = '' THEN 1 ELSE 0 END,
                rta.due_date ASC,
                pr.residual_risk DESC
        ''', (company_id,))
        treatments = cursor.fetchall()

        cursor.execute('''
            SELECT p.name, pr.risk_description, e.name, prea.probability, prea.vulnerability_level,
                   prea.impact, prea.control_effectiveness, prea.confidence, prea.evidence, prea.created_at
            FROM process_risk_expert_assessments prea
            JOIN process_risks pr ON pr.id = prea.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            JOIN experts e ON e.id = prea.expert_id
            WHERE p.company_id = ?
            ORDER BY p.name, pr.id, e.name
        ''', (company_id,))
        expert_assessments = cursor.fetchall()

        cursor.execute('''
            SELECT p.name, COUNT(pr.id),
                   SUM(CASE WHEN COALESCE(pr.risk_category, pr.risk_level) = 'Высокий' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN COALESCE(pr.risk_category, pr.risk_level) = 'Средний' THEN 1 ELSE 0 END),
                   SUM(CASE WHEN COALESCE(pr.risk_category, pr.risk_level) = 'Низкий' THEN 1 ELSE 0 END),
                   COALESCE(MAX(pr.residual_risk), 0), COALESCE(AVG(pr.residual_risk), 0)
            FROM processes p
            LEFT JOIN process_risks pr ON pr.process_id = p.id
            WHERE p.company_id = ?
            GROUP BY p.id, p.name
            ORDER BY COALESCE(MAX(pr.residual_risk), 0) DESC
        ''', (company_id,))
        process_summary = cursor.fetchall()

    package = io.BytesIO()
    with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        add_csv_to_zip(zip_file, '01_company_profile.csv', [
            'ID', 'Название', 'Отрасль', 'Описание', 'Создано'
        ], [company])
        add_csv_to_zip(zip_file, '02_process_summary.csv', [
            'Процесс', 'Всего рисков', 'Высокие', 'Средние', 'Низкие', 'Max residual', 'Avg residual'
        ], process_summary)
        add_csv_to_zip(zip_file, '03_processes.csv', [
            'ID', 'Процесс', 'Тип', 'Владелец', 'Входы', 'Выходы', 'Регуляторы', 'Ресурсы', 'Описание', 'Создано'
        ], processes)
        add_csv_to_zip(zip_file, '04_subprocesses.csv', [
            'Процесс', 'Подпроцесс', 'Ответственный', 'Системы', 'Входы', 'Выходы', 'Описание'
        ], subprocesses)
        add_csv_to_zip(zip_file, '05_assets.csv', [
            'Процесс', 'Подпроцесс', 'Актив', 'Роль в процессе', 'Life/Health', 'Economy', 'Ecology',
            'Dependency', 'Social', 'International', 'Threat probability', 'Asset evaluation votes', 'Threat probability votes'
        ], assets)
        add_csv_to_zip(zip_file, '06_process_risk_register.csv', [
            'Risk ID', 'Процесс', 'Подпроцесс', 'Актив', 'Угроза', 'Уязвимость', 'Категория уязвимости',
            'Контроль', 'Описание риска', 'Вероятность', 'Уязвимость уровень', 'Impact',
            'Initial risk', 'Control effectiveness', 'Residual risk', 'Уровень', 'Priority',
            'Статус', 'Risk owner', 'Mitigation owner', 'Due date', 'Источник', 'Confidence',
            'Evidence', 'Last reviewed', 'AI recommendation'
        ], risks)
        add_csv_to_zip(zip_file, '07_treatment_plan.csv', [
            'Action ID', 'Процесс', 'Подпроцесс', 'Риск', 'Уровень риска', 'Residual risk',
            'Мера', 'Тип', 'Owner', 'Due date', 'Cost', 'Expected residual',
            'Actual residual', 'Progress', 'Status', 'Evidence'
        ], treatments)
        add_csv_to_zip(zip_file, '08_expert_risk_assessments.csv', [
            'Процесс', 'Риск', 'Эксперт', 'Probability', 'Vulnerability', 'Impact',
            'Control effectiveness', 'Confidence', 'Evidence', 'Created at'
        ], expert_assessments)
    package.seek(0)
    return company, package

def load_data_quality_checks():
    checks = []
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute('''
            SELECT pr.id, p.name, sp.name, pr.risk_description, pr.residual_risk,
                   COALESCE(pr.risk_category, pr.risk_level), COUNT(rta.id)
            FROM process_risks pr
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            LEFT JOIN risk_treatment_actions rta ON rta.process_risk_id = pr.id
            WHERE COALESCE(pr.risk_category, pr.risk_level) = 'Высокий'
            GROUP BY pr.id, p.name, sp.name, pr.risk_description, pr.residual_risk, COALESCE(pr.risk_category, pr.risk_level)
            HAVING COUNT(rta.id) = 0
            ORDER BY pr.residual_risk DESC
        ''')
        items = [
            make_quality_item(
                f"{row[1]}{(' / ' + row[2]) if row[2] else ''}",
                row[3] or 'Описание риска не заполнено',
                url_for('edit_process_risk', id=row[0]),
                f"Residual: {row[4] or 0:.2f}, уровень: {row[5] or '-'}",
            )
            for row in cursor.fetchall()
        ]
        checks.append({
            'title': 'Высокие риски без плана обработки',
            'severity': 'critical',
            'description': 'Для продакшн-реестра каждый высокий риск должен иметь хотя бы одну меру снижения или формальное принятие.',
            'items': items,
        })

        cursor.execute('''
            SELECT rta.id, rta.title, p.name, sp.name, rta.owner, rta.due_date,
                   COALESCE(rta.status, 'Planned'), pr.residual_risk
            FROM risk_treatment_actions rta
            JOIN process_risks pr ON pr.id = rta.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            WHERE rta.due_date IS NOT NULL AND rta.due_date <> '' AND rta.due_date < DATE('now')
              AND COALESCE(rta.status, '') NOT IN ('Completed', 'Accepted', 'Cancelled')
            ORDER BY rta.due_date ASC, pr.residual_risk DESC
        ''')
        items = [
            make_quality_item(
                row[1],
                f"{row[2]}{(' / ' + row[3]) if row[3] else ''}",
                url_for('edit_risk_treatment', id=row[0]),
                f"Due: {row[5]}, статус: {row[6]}, owner: {row[4] or '-'}, residual: {row[7] or 0:.2f}",
            )
            for row in cursor.fetchall()
        ]
        checks.append({
            'title': 'Просроченные меры обработки',
            'severity': 'critical',
            'description': 'Просроченные меры снижения риска должны быть закрыты, переназначены или эскалированы.',
            'items': items,
        })

        cursor.execute('''
            SELECT pr.id, p.name, sp.name, pr.risk_description, pr.residual_risk,
                   COALESCE(pr.risk_category, pr.risk_level),
                   pr.risk_owner, pr.mitigation_owner, pr.due_date, pr.evidence, pr.last_reviewed_at
            FROM process_risks pr
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            WHERE pr.risk_owner IS NULL OR TRIM(pr.risk_owner) = ''
               OR pr.mitigation_owner IS NULL OR TRIM(pr.mitigation_owner) = ''
               OR pr.due_date IS NULL OR TRIM(pr.due_date) = ''
               OR pr.evidence IS NULL OR TRIM(pr.evidence) = ''
               OR pr.last_reviewed_at IS NULL OR TRIM(pr.last_reviewed_at) = ''
            ORDER BY pr.residual_risk DESC
        ''')
        items = []
        for row in cursor.fetchall():
            missing = []
            if not row[6]:
                missing.append('risk owner')
            if not row[7]:
                missing.append('mitigation owner')
            if not row[8]:
                missing.append('due date')
            if not row[9]:
                missing.append('evidence')
            if not row[10]:
                missing.append('last review')
            items.append(make_quality_item(
                f"{row[1]}{(' / ' + row[2]) if row[2] else ''}",
                row[3] or 'Описание риска не заполнено',
                url_for('edit_process_risk', id=row[0]),
                f"Не заполнено: {', '.join(missing)}; residual: {row[4] or 0:.2f}, уровень: {row[5] or '-'}",
            ))
        checks.append({
            'title': 'Неполные карточки рисков',
            'severity': 'warning',
            'description': 'Для аудита и управления нужны владелец риска, владелец меры, срок, доказательства и дата пересмотра.',
            'items': items,
        })

        cursor.execute('''
            SELECT a.id, a.name, COUNT(ae.id) AS vote_count
            FROM assets a
            LEFT JOIN asset_evaluations ae ON ae.asset_id = a.id
            GROUP BY a.id, a.name
            HAVING COUNT(ae.id) < 2
            ORDER BY vote_count ASC, a.name
        ''')
        items = [
            make_quality_item(
                row[1],
                'Недостаточно экспертных голосов для устойчивой оценки критичности актива.',
                url_for('list_experts'),
                f"Оценок: {row[2]} из минимум 2",
            )
            for row in cursor.fetchall()
        ]
        checks.append({
            'title': 'Активы с недостатком экспертных оценок',
            'severity': 'warning',
            'description': 'Средняя критичность должна основываться минимум на двух независимых экспертных оценках.',
            'items': items,
        })

        cursor.execute('''
            SELECT a.id, a.name, COUNT(tp.id) AS vote_count
            FROM assets a
            LEFT JOIN threat_probabilities tp ON tp.asset_id = a.id
            GROUP BY a.id, a.name
            HAVING COUNT(tp.id) < 2
            ORDER BY vote_count ASC, a.name
        ''')
        items = [
            make_quality_item(
                row[1],
                'Недостаточно голосов по вероятности угроз для IoT-актива.',
                url_for('list_experts'),
                f"Оценок: {row[2]} из минимум 2",
            )
            for row in cursor.fetchall()
        ]
        checks.append({
            'title': 'Активы с недостатком оценок вероятности угроз',
            'severity': 'warning',
            'description': 'Вероятность угроз должна подтверждаться несколькими экспертами, иначе итоговый риск легко искажается.',
            'items': items,
        })

        cursor.execute('''
            SELECT pr.id, p.name, pr.risk_description, COUNT(prea.id) AS vote_count
            FROM process_risks pr
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN process_risk_expert_assessments prea ON prea.process_risk_id = pr.id
            GROUP BY pr.id, p.name, pr.risk_description
            HAVING COUNT(prea.id) < 2
            ORDER BY vote_count ASC, p.name
        ''')
        items = [
            make_quality_item(
                row[1],
                row[2] or 'Описание риска не заполнено',
                url_for('edit_process_risk', id=row[0]),
                f"Экспертных оценок риска: {row[3]} из минимум 2",
            )
            for row in cursor.fetchall()
        ]
        checks.append({
            'title': 'Риски процессов с недостатком экспертных оценок',
            'severity': 'warning',
            'description': 'Оценка процесса должна иметь несколько экспертных голосов по вероятности, уязвимости и влиянию.',
            'items': items,
        })

        cursor.execute('''
            SELECT p.id, p.name, COUNT(pb.id) AS diagram_count
            FROM processes p
            LEFT JOIN process_bpmn pb ON pb.process_id = p.id
            GROUP BY p.id, p.name
            HAVING COUNT(pb.id) = 0
            ORDER BY p.name
        ''')
        items = [
            make_quality_item(
                row[1],
                'Нет BPMN-модели процесса.',
                url_for('process_detail', id=row[0]),
                'BPMN: 0',
            )
            for row in cursor.fetchall()
        ]
        checks.append({
            'title': 'Процессы без BPMN',
            'severity': 'info',
            'description': 'Для реального использования процесс должен иметь схему: входы, системы, участников и контрольные точки.',
            'items': items,
        })

    return checks

@app.route('/process_risks')
@login_required
def list_process_risks():
    filters = get_process_risk_filters()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        risks = fetch_process_risk_register(cursor, filters)
        cursor.execute('SELECT id, name FROM processes ORDER BY name')
        processes = cursor.fetchall()
    workflow_actions = {
        risk[0]: get_available_workflow_actions(risk[15], session.get('role'))
        for risk in risks
    }
    from datetime import date
    return render_template('process_risks.html', risks=risks, processes=processes, filters=filters, workflow_actions=workflow_actions, statuses=PROCESS_RISK_STATUSES, now=date.today().isoformat(), can_edit_risks=session.get('role') in ('admin', 'risk_manager', 'process_owner'))

@app.route('/process_risks/export.csv')
@login_required
def export_process_risks_csv():
    filters = get_process_risk_filters()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        risks = fetch_process_risk_register(cursor, filters)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'ID', 'Процесс', 'Подпроцесс', 'Актив', 'Описание риска', 'Угроза', 'Уязвимость',
        'Вероятность', 'Уязвимость уровень', 'Impact', 'Начальный риск', 'Эффективность контроля',
        'Остаточный риск', 'Уровень', 'Снижение риска', 'Priority', 'Статус', 'Risk owner',
        'Mitigation owner', 'Due date', 'Источник', 'Confidence', 'Доказательства', 'Последний пересмотр',
        'Контроль', 'AI рекомендация'
    ])
    for risk in risks:
        writer.writerow([
            risk[0], risk[1], risk[2] or '', risk[3] or '', risk[23] or '', risk[24] or '', risk[25] or '',
            risk[4], risk[11], risk[5], risk[6], risk[7], risk[8], risk[9], risk[13], risk[14],
            risk[15], risk[16] or '', risk[17] or '', risk[18] or '', risk[19] or '', risk[20] or '',
            risk[21] or '', risk[22] or '', risk[26] or '', risk[10] or ''
        ])

    return Response(
        '\ufeff' + output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=process_risk_register.csv'}
    )

@app.route('/companies/<int:company_id>/report.zip')
@login_required
def export_company_report_zip(company_id):
    result = build_company_report_package(company_id)
    if not result:
        flash('Компания не найдена!')
        return redirect(url_for('list_companies'))
    company, package = result
    filename = f"{safe_report_filename(company[1])}_risk_report.zip"
    return Response(
        package.getvalue(),
        mimetype='application/zip',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )

@app.route('/process_risks/<int:id>/workflow', methods=['POST'])
@login_required
def process_risk_workflow_action(id):
    action_key = request.form.get('action')
    comment = request.form.get('comment', '').strip()
    action = PROCESS_RISK_WORKFLOW_ACTIONS.get(action_key)
    if not action:
        flash('Некорректное действие workflow.')
        return redirect(request.referrer or url_for('list_process_risks'))

    role = session.get('role')
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, process_id, COALESCE(status, ?), risk_description FROM process_risks WHERE id = ?', ('Draft', id))
        risk = cursor.fetchone()
        if not risk:
            flash('Риск процесса не найден!')
            return redirect(url_for('list_process_risks'))

        current_status = risk[2]
        if not can_perform_workflow_action(current_status, action_key, role):
            flash('Недостаточно прав или недопустимый переход статуса.')
            return redirect(request.referrer or url_for('list_process_risks'))

        before = fetch_process_risk_snapshot(cursor, id)
        to_status = action['to_status']
        cursor.execute('''
            UPDATE process_risks
            SET status = ?, last_reviewed_at = DATE('now')
            WHERE id = ?
        ''', (to_status, id))
        cursor.execute('''
            INSERT INTO process_risk_workflow (
                process_risk_id, from_status, to_status, action, comment,
                user_id, username, role
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            id, current_status, to_status, action_key, comment or None,
            session.get('user_id'), session.get('username'), role,
        ))
        after = fetch_process_risk_snapshot(cursor, id)
        log_audit_event(
            cursor,
            'workflow',
            'process_risk',
            id,
            f"Workflow: {current_status} -> {to_status}.",
            before=before,
            after=after,
        )
        conn.commit()
    flash(f"Статус риска изменен: {current_status} -> {to_status}.")
    return redirect(request.referrer or url_for('process_detail', id=risk[1]))

@app.route('/risk_workflow')
@login_required
def risk_workflow():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT w.created_at, w.username, w.role, w.from_status, w.to_status, w.action, w.comment,
                   pr.id, p.name, sp.name, pr.risk_description, pr.residual_risk,
                   COALESCE(pr.risk_category, pr.risk_level), COALESCE(pr.status, 'Draft')
            FROM process_risk_workflow w
            JOIN process_risks pr ON pr.id = w.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            ORDER BY w.created_at DESC, w.id DESC
            LIMIT 300
        ''')
        history_rows = cursor.fetchall()
        filters = {
            'process_id': '',
            'risk_level': '',
            'priority': '',
            'status': '',
            'confidence': '',
            'owner': '',
            'overdue': '',
        }
        all_risks = fetch_process_risk_register(cursor, filters)
    if can_view_all_data():
        history = history_rows
    else:
        visible_ids = {risk[0] for risk in all_risks}
        history = [row for row in history_rows if row[7] in visible_ids]
    workflow_actions = {}
    pending = []
    for risk in all_risks:
        actions = get_available_workflow_actions(risk[15], session.get('role'))
        if actions:
            pending.append(risk)
            workflow_actions[risk[0]] = actions
    return render_template('risk_workflow.html', history=history, pending=pending, workflow_actions=workflow_actions)

@app.route('/my_tasks')
@login_required
def my_tasks():
    tasks = load_user_task_queue()
    return render_template('my_tasks.html', tasks=tasks)

@app.route('/responsibility_matrix')
@login_required
def responsibility_matrix():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        process_where = []
        process_params = []
        append_process_visibility_filter(process_where, process_params, 'p')
        process_where_sql = f"WHERE {' AND '.join(process_where)}" if process_where else ''
        cursor.execute(f'''
            SELECT p.id, p.name, c.name, p.owner, pu.username, pu.role,
                   COUNT(DISTINCT pr.id),
                   SUM(CASE WHEN COALESCE(pr.risk_category, pr.risk_level) = 'Высокий' THEN 1 ELSE 0 END),
                   COUNT(DISTINCT rta.id)
            FROM processes p
            JOIN companies c ON c.id = p.company_id
            LEFT JOIN users pu ON pu.id = p.owner_user_id
            LEFT JOIN process_risks pr ON pr.process_id = p.id
            LEFT JOIN risk_treatment_actions rta ON rta.process_risk_id = pr.id
            {process_where_sql}
            GROUP BY p.id, p.name, c.name, p.owner, pu.username, pu.role
            ORDER BY c.name, p.name
        ''', process_params)
        processes = cursor.fetchall()

        risk_where = []
        risk_params = []
        append_process_risk_visibility_filter(risk_where, risk_params, 'p', 'pr')
        risk_where_sql = f"WHERE {' AND '.join(risk_where)}" if risk_where else ''
        cursor.execute(f'''
            SELECT pr.id, p.name, sp.name, pr.risk_description, COALESCE(pr.risk_category, pr.risk_level),
                   pr.residual_risk, COALESCE(pr.status, 'Draft'),
                   pr.risk_owner, ru.username, ru.role,
                   pr.mitigation_owner, mu.username, mu.role,
                   pr.due_date
            FROM process_risks pr
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            LEFT JOIN users ru ON ru.id = pr.risk_owner_user_id
            LEFT JOIN users mu ON mu.id = pr.mitigation_owner_user_id
            {risk_where_sql}
            ORDER BY pr.residual_risk DESC
        ''', risk_params)
        risks = cursor.fetchall()

        treatment_where = []
        treatment_params = []
        append_treatment_visibility_filter(treatment_where, treatment_params, 'p', 'pr', 'rta')
        treatment_where_sql = f"WHERE {' AND '.join(treatment_where)}" if treatment_where else ''
        cursor.execute(f'''
            SELECT rta.id, rta.title, p.name, pr.risk_description, rta.owner, u.username, u.role,
                   rta.due_date, rta.progress, COALESCE(rta.status, 'Planned'), pr.residual_risk
            FROM risk_treatment_actions rta
            JOIN process_risks pr ON pr.id = rta.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN users u ON u.id = rta.owner_user_id
            {treatment_where_sql}
            ORDER BY
                CASE WHEN rta.due_date IS NULL OR rta.due_date = '' THEN 1 ELSE 0 END,
                rta.due_date ASC,
                pr.residual_risk DESC
        ''', treatment_params)
        treatments = cursor.fetchall()

    summary = {
        'processes_without_owner': sum(1 for row in processes if not row[4] and not row[3]),
        'risks_without_owner': sum(1 for row in risks if not row[8] and not row[7]),
        'risks_without_mitigation_owner': sum(1 for row in risks if not row[11] and not row[10]),
        'treatments_without_owner': sum(1 for row in treatments if not row[5] and not row[4]),
    }
    return render_template('responsibility_matrix.html', processes=processes, risks=risks, treatments=treatments, summary=summary)

@app.route('/operational_analytics')
@login_required
def operational_analytics():
    analytics = load_operational_analytics()
    return render_template('operational_analytics.html', analytics=analytics)

@app.route('/compliance')
@login_required
def compliance_dashboard():
    compliance = load_compliance_dashboard()
    return render_template('compliance.html', compliance=compliance)

@app.route('/compliance/evidence/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_compliance_evidence(id):
    if session.get('role') == 'auditor':
        flash('Аудитор может просматривать соответствие, но не редактировать evidence.')
        return redirect(url_for('compliance_dashboard'))
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ce.id, ce.requirement_id, ce.treatment_id, ce.status, ce.evidence, ce.owner_user_id,
                   s.name, s.version, r.code, r.title, r.domain, r.description,
                   rta.title, p.name
            FROM compliance_evidence ce
            JOIN compliance_requirements r ON r.id = ce.requirement_id
            JOIN compliance_standards s ON s.id = r.standard_id
            LEFT JOIN risk_treatment_actions rta ON rta.id = ce.treatment_id
            LEFT JOIN process_risks pr ON pr.id = rta.process_risk_id
            LEFT JOIN processes p ON p.id = pr.process_id
            WHERE ce.id = ?
        ''', (id,))
        item = cursor.fetchone()
        if not item:
            flash('Evidence не найден.')
            return redirect(url_for('compliance_dashboard'))
        if item[2] and not user_can_edit_treatment(cursor, item[2]) and session.get('role') != 'admin':
            flash('Доступ запрещён к редактированию этого evidence.')
            return redirect(url_for('compliance_dashboard'))
        if request.method == 'POST':
            cursor.execute('''
                UPDATE compliance_evidence
                SET status = ?, evidence = ?, owner_user_id = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (
                request.form.get('status') or 'Not assessed',
                request.form.get('evidence'),
                request.form.get('owner_user_id') or None,
                id,
            ))
            log_audit_event(cursor, 'update', 'compliance_evidence', id, 'Обновлен статус соответствия.')
            conn.commit()
            flash('Статус соответствия обновлен.')
            return redirect(url_for('compliance_dashboard'))
        users = load_user_options(cursor)
    statuses = ['Not assessed', 'Gap', 'Partially implemented', 'Implemented', 'Verified']
    return render_template('compliance_evidence_form.html', item=item, users=users, statuses=statuses)

@app.route('/process_risks/add', methods=['GET', 'POST'])
@risk_editor_required
def add_process_risk():
    process_id = request.args.get('process_id') or request.form.get('process_id')
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if request.method == 'POST':
            metrics = calculate_process_risk_from_form(request.form, cursor)
            control_measure_id = request.form.get('control_measure_id') or None
            risk_owner_user_id = request.form.get('risk_owner_user_id') or None
            mitigation_owner_user_id = request.form.get('mitigation_owner_user_id') or None
            ai_recommendation = recommend_process_risk(metrics['residual_risk'], metrics['control_effectiveness'], control_measure_id, metrics['risk_category'], metrics['vulnerability_level'])
            cursor.execute('''
                INSERT INTO process_risks (
                    process_id, subprocess_id, asset_id, threat_id, vulnerability_id, control_measure_id, risk_description,
                    probability, vulnerability_level, impact, initial_risk, control_effectiveness, residual_risk,
                    risk_level, risk_category, cost, risk_reduction, priority, ai_recommendation,
                    status, risk_owner, mitigation_owner, risk_owner_user_id, mitigation_owner_user_id, due_date,
                    assessment_source, confidence, evidence, last_reviewed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                int(request.form['process_id']), request.form.get('subprocess_id') or None, request.form.get('asset_id') or None,
                request.form.get('threat_id') or None, request.form.get('vulnerability_id') or None, control_measure_id,
                request.form.get('risk_description'), metrics['probability'], metrics['vulnerability_level'], metrics['impact'],
                metrics['initial_risk'], metrics['control_effectiveness'], metrics['residual_risk'],
                metrics['risk_level'], metrics['risk_category'], metrics['cost'], metrics['risk_reduction'],
                metrics['priority'], ai_recommendation, request.form.get('status') or 'Draft',
                request.form.get('risk_owner'), request.form.get('mitigation_owner'), risk_owner_user_id, mitigation_owner_user_id,
                request.form.get('due_date'),
                request.form.get('assessment_source') or 'Expert', request.form.get('confidence') or 'Medium',
                request.form.get('evidence'), request.form.get('last_reviewed_at')
            ))
            risk_id = cursor.lastrowid
            after = fetch_process_risk_snapshot(cursor, risk_id)
            log_audit_event(
                cursor,
                'create',
                'process_risk',
                risk_id,
                'Создан риск процесса.',
                after=after,
            )
            conn.commit()
            flash('Риск процесса создан!')
            return redirect(url_for('process_detail', id=int(request.form['process_id'])))
        form_data = load_process_risk_form_data(cursor)
    return render_template('process_risk_form.html', risk=None, form_data=form_data, selected_process_id=int(process_id) if process_id else None, statuses=PROCESS_RISK_STATUSES)

@app.route('/process_risks/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_process_risk(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if not user_can_edit_process_risk(cursor, id):
            flash('Доступ запрещён к редактированию этого риска.')
            return redirect(url_for('list_process_risks'))
        cursor.execute('''
            SELECT id, process_id, subprocess_id, asset_id, threat_id, vulnerability_id, control_measure_id, risk_description,
                   probability, vulnerability_level, impact, initial_risk, control_effectiveness, residual_risk,
                   risk_level, risk_category, cost, risk_reduction, priority, ai_recommendation,
                   COALESCE(status, 'Draft'), risk_owner, mitigation_owner, due_date,
                   COALESCE(assessment_source, 'Expert'), COALESCE(confidence, 'Medium'), evidence, last_reviewed_at,
                   risk_owner_user_id, mitigation_owner_user_id
            FROM process_risks WHERE id = ?
        ''', (id,))
        risk = cursor.fetchone()
        if not risk:
            flash('Риск процесса не найден!')
            return redirect(url_for('list_process_risks'))
        if request.method == 'POST':
            before = fetch_process_risk_snapshot(cursor, id)
            metrics = calculate_process_risk_from_form(request.form, cursor)
            control_measure_id = request.form.get('control_measure_id') or None
            risk_owner_user_id = request.form.get('risk_owner_user_id') or None
            mitigation_owner_user_id = request.form.get('mitigation_owner_user_id') or None
            ai_recommendation = recommend_process_risk(metrics['residual_risk'], metrics['control_effectiveness'], control_measure_id, metrics['risk_category'], metrics['vulnerability_level'])
            cursor.execute('''
                UPDATE process_risks
                SET process_id = ?, subprocess_id = ?, asset_id = ?, threat_id = ?, vulnerability_id = ?, control_measure_id = ?,
                    risk_description = ?, probability = ?, vulnerability_level = ?, impact = ?, initial_risk = ?, control_effectiveness = ?,
                    residual_risk = ?, risk_level = ?, risk_category = ?, cost = ?, risk_reduction = ?, priority = ?, ai_recommendation = ?,
                    status = ?, risk_owner = ?, mitigation_owner = ?, due_date = ?, assessment_source = ?, confidence = ?,
                    evidence = ?, last_reviewed_at = ?, risk_owner_user_id = ?, mitigation_owner_user_id = ?
                WHERE id = ?
            ''', (
                int(request.form['process_id']), request.form.get('subprocess_id') or None, request.form.get('asset_id') or None,
                request.form.get('threat_id') or None, request.form.get('vulnerability_id') or None, control_measure_id,
                request.form.get('risk_description'), metrics['probability'], metrics['vulnerability_level'], metrics['impact'],
                metrics['initial_risk'], metrics['control_effectiveness'], metrics['residual_risk'], metrics['risk_level'],
                metrics['risk_category'], metrics['cost'], metrics['risk_reduction'], metrics['priority'], ai_recommendation,
                request.form.get('status') or 'Draft', request.form.get('risk_owner'),
                request.form.get('mitigation_owner'), request.form.get('due_date'), request.form.get('assessment_source') or 'Expert',
                request.form.get('confidence') or 'Medium', request.form.get('evidence'), request.form.get('last_reviewed_at'),
                risk_owner_user_id, mitigation_owner_user_id, id
            ))
            after = fetch_process_risk_snapshot(cursor, id)
            log_audit_event(
                cursor,
                'update',
                'process_risk',
                id,
                'Обновлен риск процесса.',
                before=before,
                after=after,
            )
            conn.commit()
            flash('Риск процесса обновлен!')
            return redirect(url_for('process_detail', id=int(request.form['process_id'])))
        form_data = load_process_risk_form_data(cursor)
    return render_template('process_risk_form.html', risk=risk, form_data=form_data, selected_process_id=None, statuses=PROCESS_RISK_STATUSES)

@app.route('/process_risks/delete/<int:id>', methods=['POST'])
@admin_required
def delete_process_risk(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT process_id FROM process_risks WHERE id = ?', (id,))
        row = cursor.fetchone()
        if row:
            before = fetch_process_risk_snapshot(cursor, id)
            cursor.execute('DELETE FROM process_risk_workflow WHERE process_risk_id = ?', (id,))
            cursor.execute('DELETE FROM process_risks WHERE id = ?', (id,))
            log_audit_event(
                cursor,
                'delete',
                'process_risk',
                id,
                'Удален риск процесса.',
                before=before,
            )
            conn.commit()
            flash('Риск процесса удален!')
            return redirect(url_for('process_detail', id=row[0]))
    return redirect(url_for('list_process_risks'))

@app.route('/risk_treatments')
@login_required
def list_risk_treatments():
    filters = {
        'status': request.args.get('status', ''),
        'owner': request.args.get('owner', '').strip(),
        'overdue': request.args.get('overdue', ''),
    }
    where = []
    params = []
    if filters['status']:
        where.append("COALESCE(rta.status, 'Planned') = ?")
        params.append(filters['status'])
    if filters['owner']:
        where.append('rta.owner LIKE ?')
        params.append(f"%{filters['owner']}%")
    if filters['overdue']:
        where.append("rta.due_date IS NOT NULL AND rta.due_date <> '' AND rta.due_date < DATE('now') AND COALESCE(rta.status, '') NOT IN ('Completed', 'Cancelled')")
    append_treatment_visibility_filter(where, params, 'p', 'pr', 'rta')
    where_sql = f"WHERE {' AND '.join(where)}" if where else ''
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(f'''
            SELECT rta.id, p.name, sp.name, pr.risk_description, COALESCE(pr.risk_category, pr.risk_level),
                   pr.residual_risk, rta.title, rta.treatment_type, rta.owner, rta.due_date,
                   rta.cost, rta.expected_residual_risk, rta.actual_residual_risk, rta.progress,
                   COALESCE(rta.status, 'Planned'), rta.evidence, pr.id
            FROM risk_treatment_actions rta
            JOIN process_risks pr ON pr.id = rta.process_risk_id
            JOIN processes p ON p.id = pr.process_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            {where_sql}
            ORDER BY
                CASE WHEN rta.due_date IS NULL OR rta.due_date = '' THEN 1 ELSE 0 END,
                rta.due_date ASC,
                pr.residual_risk DESC
        ''', params)
        treatments = cursor.fetchall()
    from datetime import date
    return render_template('risk_treatments.html', treatments=treatments, filters=filters, now=date.today().isoformat(), can_edit_treatments=session.get('role') in ('admin', 'risk_manager', 'process_owner'))

@app.route('/risk_treatments/add', methods=['GET', 'POST'])
@risk_editor_required
def add_risk_treatment():
    selected_risk_id = request.args.get('process_risk_id') or request.form.get('process_risk_id')
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if request.method == 'POST':
            progress = int(request.form.get('progress') or 0)
            progress = max(0, min(100, progress))
            cursor.execute('''
                INSERT INTO risk_treatment_actions (
                    process_risk_id, title, description, treatment_type, owner, due_date, cost,
                    expected_residual_risk, actual_residual_risk, progress, status, evidence, owner_user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                int(request.form['process_risk_id']), request.form['title'], request.form.get('description'),
                request.form.get('treatment_type') or 'Mitigate', request.form.get('owner'), request.form.get('due_date'),
                float(request.form.get('cost') or 0), request.form.get('expected_residual_risk') or None,
                request.form.get('actual_residual_risk') or None, progress, request.form.get('status') or 'Planned',
                request.form.get('evidence'), request.form.get('owner_user_id') or None,
            ))
            treatment_id = cursor.lastrowid
            after = fetch_risk_treatment_snapshot(cursor, treatment_id)
            log_audit_event(cursor, 'create', 'risk_treatment', treatment_id, 'Создана мера обработки риска.', after=after)
            conn.commit()
            flash('Мера обработки риска создана!')
            return redirect(url_for('list_risk_treatments'))
        process_risks = load_treatment_risk_options(cursor)
        users = load_user_options(cursor)
    return render_template('risk_treatment_form.html', treatment=None, process_risks=process_risks, selected_risk_id=int(selected_risk_id) if selected_risk_id else None, users=users)

@app.route('/risk_treatments/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_risk_treatment(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if not user_can_edit_treatment(cursor, id):
            flash('Доступ запрещён к редактированию этой меры.')
            return redirect(url_for('list_risk_treatments'))
        cursor.execute('''
            SELECT id, process_risk_id, title, description, treatment_type, owner, due_date, cost,
                   expected_residual_risk, actual_residual_risk, progress, status, evidence, owner_user_id
            FROM risk_treatment_actions
            WHERE id = ?
        ''', (id,))
        treatment = cursor.fetchone()
        if not treatment:
            flash('Мера обработки риска не найдена!')
            return redirect(url_for('list_risk_treatments'))
        if request.method == 'POST':
            before = fetch_risk_treatment_snapshot(cursor, id)
            progress = int(request.form.get('progress') or 0)
            progress = max(0, min(100, progress))
            cursor.execute('''
                UPDATE risk_treatment_actions
                SET process_risk_id = ?, title = ?, description = ?, treatment_type = ?, owner = ?,
                    due_date = ?, cost = ?, expected_residual_risk = ?, actual_residual_risk = ?,
                    progress = ?, status = ?, evidence = ?, owner_user_id = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (
                int(request.form['process_risk_id']), request.form['title'], request.form.get('description'),
                request.form.get('treatment_type') or 'Mitigate', request.form.get('owner'), request.form.get('due_date'),
                float(request.form.get('cost') or 0), request.form.get('expected_residual_risk') or None,
                request.form.get('actual_residual_risk') or None, progress, request.form.get('status') or 'Planned',
                request.form.get('evidence'), request.form.get('owner_user_id') or None, id,
            ))
            after = fetch_risk_treatment_snapshot(cursor, id)
            log_audit_event(cursor, 'update', 'risk_treatment', id, 'Обновлена мера обработки риска.', before=before, after=after)
            conn.commit()
            flash('Мера обработки риска обновлена!')
            return redirect(url_for('list_risk_treatments'))
        process_risks = load_treatment_risk_options(cursor)
        users = load_user_options(cursor)
    return render_template('risk_treatment_form.html', treatment=treatment, process_risks=process_risks, selected_risk_id=None, users=users)

@app.route('/risk_treatments/delete/<int:id>', methods=['POST'])
@admin_required
def delete_risk_treatment(id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        before = fetch_risk_treatment_snapshot(cursor, id)
        if not before:
            flash('Мера обработки риска не найдена!')
            return redirect(url_for('list_risk_treatments'))
        cursor.execute('DELETE FROM compliance_evidence WHERE treatment_id = ?', (id,))
        cursor.execute('DELETE FROM risk_treatment_actions WHERE id = ?', (id,))
        log_audit_event(cursor, 'delete', 'risk_treatment', id, 'Удалена мера обработки риска.', before=before)
        conn.commit()
    flash('Мера обработки риска удалена!')
    return redirect(url_for('list_risk_treatments'))


def load_process_risk_form_data(cursor):
    cursor.execute('SELECT id, name, owner, owner_user_id FROM processes ORDER BY name')
    processes = cursor.fetchall()
    cursor.execute('SELECT id, process_id, name, responsible_person FROM subprocesses ORDER BY process_id, COALESCE(order_index, 9999), name')
    subprocesses = cursor.fetchall()
    cursor.execute('SELECT id, name FROM assets ORDER BY name')
    assets = cursor.fetchall()
    cursor.execute('''
        SELECT pa.process_id, a.id, a.name, pa.role_in_process
        FROM process_assets pa
        JOIN assets a ON a.id = pa.asset_id
        ORDER BY pa.process_id, a.name
    ''')
    process_assets = cursor.fetchall()
    cursor.execute('SELECT id, name FROM threats ORDER BY name')
    threats = cursor.fetchall()
    cursor.execute('SELECT id, name, category FROM vulnerabilities ORDER BY category, name')
    vulnerabilities = cursor.fetchall()
    cursor.execute('SELECT id, name FROM control_measures ORDER BY name')
    controls = cursor.fetchall()
    return {
        'processes': processes,
        'subprocesses': subprocesses,
        'assets': assets,
        'process_assets': process_assets,
        'threats': threats,
        'vulnerabilities': vulnerabilities,
        'controls': controls,
        'users': load_user_options(cursor),
    }

def parse_bpmn_json(bpmn_json):
    if not bpmn_json:
        return {'nodes': [], 'edges': [], 'edge_labels': {}, 'incoming': {}, 'outgoing': {}, 'layout': {'nodes': [], 'edges': [], 'width': 0, 'height': 0}}
    try:
        parsed = json.loads(bpmn_json)
    except (TypeError, json.JSONDecodeError):
        return {'nodes': [], 'edges': [], 'edge_labels': {}, 'incoming': {}, 'outgoing': {}, 'layout': {'nodes': [], 'edges': [], 'width': 0, 'height': 0}, 'raw': bpmn_json}

    nodes = parsed.get('nodes', [])
    edges = parsed.get('edges', [])
    node_ids = {node.get('id') for node in nodes}
    incoming = {node_id: [] for node_id in node_ids}
    outgoing = {node_id: [] for node_id in node_ids}
    edge_labels = {}
    for edge in edges:
        source = edge.get('from')
        target = edge.get('to')
        if source in outgoing:
            outgoing[source].append(target)
        if target in incoming:
            incoming[target].append(source)
        if edge.get('label'):
            edge_labels[(source, target)] = edge.get('label')

    layout = build_bpmn_layout(nodes, edges, edge_labels)
    return {
        'nodes': nodes,
        'edges': edges,
        'edge_labels': edge_labels,
        'incoming': incoming,
        'outgoing': outgoing,
        'layout': layout,
        'raw': bpmn_json,
    }

def risk_class_from_score(score):
    if score is None:
        return 'none'
    if score >= 7:
        return 'high'
    if score >= 4:
        return 'medium'
    return 'low'

def get_bpmn_subprocess_risk_summary(cursor, process_id):
    cursor.execute('''
        SELECT sp.id, sp.name, COALESCE(MAX(pr.residual_risk), 0), COUNT(pr.id)
        FROM subprocesses sp
        LEFT JOIN process_risks pr ON pr.subprocess_id = sp.id
        WHERE sp.process_id = ?
        GROUP BY sp.id, sp.name
    ''', (process_id,))
    summary = {}
    for subprocess_id, name, max_risk, risk_count in cursor.fetchall():
        score = round(max_risk or 0, 2)
        summary[str(subprocess_id)] = {
            'id': subprocess_id,
            'name': name,
            'max_residual_risk': score,
            'risk_count': risk_count or 0,
            'risk_class': risk_class_from_score(score if risk_count else None),
            'risk_category': classify_numeric_risk(score) if risk_count else 'Нет риска',
        }
    return summary

def normalize_match_tokens(value):
    tokens = []
    for raw_token in (value or '').lower().replace('-', ' ').replace('_', ' ').split():
        token = ''.join(char for char in raw_token if char.isalnum())
        if len(token) >= 4:
            tokens.append(token)
    return tokens

def infer_bpmn_subprocess_id(node, subprocess_risks):
    if (node.get('type') or '').lower() in ('start', 'end'):
        return None
    label_tokens = normalize_match_tokens(node.get('label') or node.get('name') or node.get('id'))
    if not label_tokens:
        return None

    best_id = None
    best_score = 0
    for subprocess_id, summary in subprocess_risks.items():
        name_tokens = normalize_match_tokens(summary.get('name'))
        score = 0
        for label_token in label_tokens:
            for name_token in name_tokens:
                if label_token == name_token or label_token.startswith(name_token[:5]) or name_token.startswith(label_token[:5]):
                    score += 1
        if score > best_score:
            best_score = score
            best_id = subprocess_id
    return int(best_id) if best_id and best_score else None

def enrich_bpmn_model_with_risks(bpmn_model, subprocess_risks):
    for node in bpmn_model.get('nodes', []):
        subprocess_id = node.get('subprocess_id')
        if not subprocess_id and 'subprocess_id' not in node:
            subprocess_id = infer_bpmn_subprocess_id(node, subprocess_risks)
            if subprocess_id:
                node['subprocess_id'] = subprocess_id
        summary = subprocess_risks.get(str(subprocess_id)) if subprocess_id else None
        node['risk_score'] = summary['max_residual_risk'] if summary else None
        node['risk_category'] = summary['risk_category'] if summary else 'Не связан'
        node['risk_class'] = summary['risk_class'] if summary else 'none'

    node_meta = {node.get('id'): node for node in bpmn_model.get('nodes', [])}
    for node in bpmn_model.get('layout', {}).get('nodes', []):
        meta = node_meta.get(node.get('id'), {})
        node['subprocess_id'] = meta.get('subprocess_id')
        node['risk_score'] = meta.get('risk_score')
        node['risk_category'] = meta.get('risk_category')
        node['risk_class'] = meta.get('risk_class') or 'none'
    return bpmn_model

def build_bpmn_business_context(cursor, process_id, bpmn_model):
    cursor.execute('''
        SELECT id, name, description, input_data, output_data, responsible_person, used_systems, order_index
        FROM subprocesses
        WHERE process_id = ?
    ''', (process_id,))
    subprocesses = {
        row[0]: {
            'id': row[0],
            'name': row[1],
            'description': row[2] or '',
            'input_data': row[3] or '',
            'output_data': row[4] or '',
            'responsible_person': row[5] or '',
            'used_systems': row[6] or '',
            'order_index': row[7],
        }
        for row in cursor.fetchall()
    }

    cursor.execute('''
        SELECT pr.id, pr.subprocess_id, pr.risk_description, pr.initial_risk, pr.residual_risk,
               COALESCE(pr.risk_category, pr.risk_level), pr.priority, pr.ai_recommendation
        FROM process_risks pr
        WHERE pr.process_id = ?
        ORDER BY pr.residual_risk DESC
    ''', (process_id,))
    risks_by_subprocess = {}
    for row in cursor.fetchall():
        subprocess_id = row[1]
        if not subprocess_id:
            continue
        risks_by_subprocess.setdefault(subprocess_id, []).append({
            'id': row[0],
            'description': row[2] or '',
            'initial_risk': round(row[3] or 0, 2),
            'residual_risk': round(row[4] or 0, 2),
            'risk_reduction': round((row[3] or 0) - (row[4] or 0), 2),
            'risk_category': row[5] or '',
            'priority': row[6] or '',
            'ai_recommendation': row[7] or '',
        })

    items = []
    by_subprocess = {}
    for node in bpmn_model.get('nodes', []):
        subprocess_id = node.get('subprocess_id')
        subprocess = subprocesses.get(subprocess_id)
        risks = risks_by_subprocess.get(subprocess_id, []) if subprocess_id else []
        max_residual = max((risk['residual_risk'] for risk in risks), default=0)
        context = {
            'node_id': node.get('id'),
            'node_label': node.get('label') or node.get('name') or node.get('id'),
            'node_type': node.get('type') or 'task',
            'subprocess_id': subprocess_id,
            'subprocess': subprocess,
            'risks': risks,
            'risk_count': len(risks),
            'max_residual_risk': round(max_residual, 2),
            'risk_category': classify_numeric_risk(max_residual) if risks else 'Нет риска',
            'risk_class': risk_class_from_score(max_residual if risks else None),
        }
        items.append(context)
        if subprocess_id:
            by_subprocess[str(subprocess_id)] = context
    return {'items': items, 'by_subprocess': by_subprocess}

def build_bpmn_critical_path(bpmn_model, max_paths=250):
    nodes = bpmn_model.get('nodes', [])
    if not nodes:
        return {'best': None, 'paths': [], 'truncated': False}

    nodes_by_id = {node.get('id'): node for node in nodes if node.get('id')}
    outgoing = bpmn_model.get('outgoing') or {}
    incoming = bpmn_model.get('incoming') or {}
    edge_labels = bpmn_model.get('edge_labels') or {}

    start_ids = [
        node_id for node_id, node in nodes_by_id.items()
        if (node.get('type') or '').lower() == 'start'
    ] or [
        node_id for node_id in nodes_by_id
        if not incoming.get(node_id)
    ] or [next(iter(nodes_by_id))]

    end_ids = {
        node_id for node_id, node in nodes_by_id.items()
        if (node.get('type') or '').lower() == 'end'
    } or {
        node_id for node_id in nodes_by_id
        if not outgoing.get(node_id)
    }

    def node_score(node_id):
        try:
            return float(nodes_by_id[node_id].get('risk_score') or 0)
        except (TypeError, ValueError):
            return 0

    def node_label(node_id):
        node = nodes_by_id.get(node_id, {})
        return node.get('label') or node.get('name') or node_id

    paths = []
    truncated = False

    def add_path(path):
        total_score = round(sum(node_score(node_id) for node_id in path), 2)
        high_nodes = [
            node_id for node_id in path
            if (nodes_by_id.get(node_id, {}).get('risk_class') == 'high')
        ]
        edge_keys = [f'{path[index]}->{path[index + 1]}' for index in range(len(path) - 1)]
        paths.append({
            'node_ids': path,
            'edge_keys': edge_keys,
            'labels': [node_label(node_id) for node_id in path],
            'score': total_score,
            'risk_category': classify_numeric_risk(total_score / max(1, len([node_id for node_id in path if node_score(node_id) > 0]))) if total_score else 'Нет риска',
            'high_count': len(high_nodes),
            'high_labels': [node_label(node_id) for node_id in high_nodes],
            'edge_labels': [
                edge_labels.get((path[index], path[index + 1])) or ''
                for index in range(len(path) - 1)
            ],
        })

    def walk(node_id, path):
        nonlocal truncated
        if truncated:
            return
        if len(paths) >= max_paths:
            truncated = True
            return
        if node_id in end_ids and len(path) > 1:
            add_path(path)
            return
        next_ids = [next_id for next_id in outgoing.get(node_id, []) if next_id in nodes_by_id]
        if not next_ids:
            add_path(path)
            return
        for next_id in next_ids:
            if next_id in path:
                continue
            walk(next_id, path + [next_id])

    for start_id in start_ids:
        walk(start_id, [start_id])

    paths.sort(key=lambda item: (item['score'], item['high_count'], len(item['node_ids'])), reverse=True)
    top_paths = paths[:5]
    return {
        'best': top_paths[0] if top_paths else None,
        'paths': top_paths,
        'truncated': truncated,
    }

def build_bpmn_quality_summary(bpmn_model, subprocesses):
    nodes = bpmn_model.get('nodes', [])
    edges = bpmn_model.get('edges', [])
    node_ids = [node.get('id') for node in nodes if node.get('id')]
    node_id_set = set(node_ids)
    issues = []

    subprocess_map = {
        str(row[0]): row[1]
        for row in subprocesses
    }
    task_nodes = [
        node for node in nodes
        if (node.get('type') or 'task').lower() not in ('start', 'end', 'gateway')
    ]
    linked_subprocess_ids = {
        str(node.get('subprocess_id'))
        for node in task_nodes
        if node.get('subprocess_id')
    }

    def add_issue(level, title, detail):
        issues.append({'level': level, 'title': title, 'detail': detail})

    duplicate_ids = sorted({node_id for node_id in node_ids if node_ids.count(node_id) > 1})
    broken_edges = [
        edge for edge in edges
        if edge.get('from') not in node_id_set or edge.get('to') not in node_id_set or edge.get('from') == edge.get('to')
    ]
    starts = [node for node in nodes if (node.get('type') or '').lower() == 'start']
    ends = [node for node in nodes if (node.get('type') or '').lower() == 'end']
    unlinked_tasks = [
        node for node in task_nodes
        if not node.get('subprocess_id')
    ]
    missing_subprocesses = [
        name for subprocess_id, name in subprocess_map.items()
        if subprocess_id not in linked_subprocess_ids
    ]
    incoming = bpmn_model.get('incoming') or {}
    outgoing = bpmn_model.get('outgoing') or {}
    isolated_nodes = [
        node for node in nodes
        if not incoming.get(node.get('id')) and not outgoing.get(node.get('id'))
    ]

    if not nodes:
        add_issue('error', 'BPMN не задан', 'Для процесса нет сохраненной схемы.')
    if duplicate_ids:
        add_issue('error', 'Повторяются ID узлов', ', '.join(duplicate_ids))
    if broken_edges:
        add_issue('error', 'Некорректные связи', f'Количество проблемных связей: {len(broken_edges)}.')
    if len(starts) != 1:
        add_issue('warning', 'Стартовое событие', f'Ожидается 1 старт, сейчас: {len(starts)}.')
    if not ends:
        add_issue('warning', 'Нет финального события', 'Маршрут процесса должен явно завершаться.')
    if unlinked_tasks:
        add_issue(
            'warning',
            'Задачи без подпроцесса',
            ', '.join(node.get('label') or node.get('id') for node in unlinked_tasks)
        )
    if missing_subprocesses:
        add_issue('warning', 'Не все подпроцессы показаны на BPMN', ', '.join(missing_subprocesses))
    if isolated_nodes:
        add_issue(
            'warning',
            'Изолированные узлы',
            ', '.join(node.get('label') or node.get('id') for node in isolated_nodes)
        )

    subprocess_ids = set(subprocess_map.keys())
    linked_valid_subprocess_ids = linked_subprocess_ids & subprocess_ids
    subprocess_coverage = round((len(linked_valid_subprocess_ids) / max(1, len(subprocess_ids))) * 100, 1)
    checks = [
        bool(nodes),
        len(starts) == 1,
        bool(ends),
        not duplicate_ids and not broken_edges,
        not isolated_nodes,
        not unlinked_tasks,
        subprocess_coverage == 100 if subprocess_ids else True,
    ]
    passed_checks = sum(1 for passed in checks if passed)
    score = round((passed_checks / len(checks)) * 100)
    if score >= 85:
        status = 'Готово'
        status_class = 'ok'
    elif score >= 60:
        status = 'Нужны правки'
        status_class = 'warning'
    else:
        status = 'Критично'
        status_class = 'error'

    return {
        'score': score,
        'status': status,
        'status_class': status_class,
        'issues': issues,
        'node_count': len(nodes),
        'edge_count': len(edges),
        'linked_task_count': len(task_nodes) - len(unlinked_tasks),
        'task_count': len(task_nodes),
        'passed_checks': passed_checks,
        'total_checks': len(checks),
        'subprocess_coverage': subprocess_coverage,
    }

def get_bpmn_node_size(node_type, label, stored_width=None, stored_height=None):
    label_length = len(label or '')
    if node_type in ('start', 'end'):
        min_width = min(110, max(88, label_length * 5.5))
        min_height = min_width
    elif node_type == 'gateway':
        min_width = min(112, max(96, label_length * 5.5))
        min_height = min_width
    else:
        min_width = min(180, max(168, label_length * 6.2))
        min_height = 88 if label_length <= 36 else 96

    width = max(float(stored_width or 0), min_width)
    height = max(float(stored_height or 0), min_height)
    if node_type in ('start', 'end', 'gateway'):
        width = height = max(width, height)
    return width, height

def wrap_bpmn_label(label, width, node_type):
    max_lines = 3 if node_type in ('start', 'end', 'gateway') else 4
    chars_per_line = max(8, int(width / 7.4))
    lines = textwrap.wrap(str(label or ''), width=chars_per_line, max_lines=max_lines, placeholder='...')
    return lines or ['']

def build_bpmn_layout(nodes, edges, edge_labels):
    if not nodes:
        return {'nodes': [], 'edges': [], 'width': 0, 'height': 0}

    if any(node.get('x') is not None and node.get('y') is not None for node in nodes):
        positioned = {}
        layout_nodes = []
        max_x = 0
        max_y = 0

        for index, node in enumerate(nodes):
            node_id = node.get('id')
            node_type = node.get('type') or 'task'
            label = node.get('label') or node.get('name') or node_id
            stored_width = float(node.get('width') or (96 if node_type in ('start', 'end', 'gateway') else 150))
            stored_height = float(node.get('height') or (96 if node_type == 'gateway' else 74))
            width, height = get_bpmn_node_size(node_type, label, stored_width, stored_height)
            try:
                x = float(node.get('x')) - (width - stored_width) / 2
                y = float(node.get('y')) - (height - stored_height) / 2
            except (TypeError, ValueError):
                x = 90 + index * 190
                y = 110
            label_lines = wrap_bpmn_label(label, width, node_type)

            item = {
                'id': node_id,
                'type': node_type,
                'label': label,
                'label_lines': label_lines,
                'label_start_dy': round(-((len(label_lines) - 1) * 14) / 2, 2),
                'subprocess_id': node.get('subprocess_id'),
                'risk_score': node.get('risk_score'),
                'risk_category': node.get('risk_category'),
                'risk_class': node.get('risk_class') or 'none',
                'x': round(x, 2),
                'y': round(y, 2),
                'cx': round(x + width / 2, 2),
                'cy': round(y + height / 2, 2),
                'width': round(width, 2),
                'height': round(height, 2),
            }
            positioned[node_id] = item
            layout_nodes.append(item)
            max_x = max(max_x, x + width)
            max_y = max(max_y, y + height)

        layout_edges = []
        for edge in edges:
            source = positioned.get(edge.get('from'))
            target = positioned.get(edge.get('to'))
            if not source or not target:
                continue
            route = build_bpmn_edge_route(source, target)
            layout_edges.append({
                'from': edge.get('from'),
                'to': edge.get('to'),
                'label': edge.get('label') or edge_labels.get((edge.get('from'), edge.get('to'))),
                'path': route['path'],
                'label_x': route['label_x'],
                'label_y': route['label_y'],
            })

        return {
            'nodes': layout_nodes,
            'edges': layout_edges,
            'width': round(max(720, max_x + 100), 2),
            'height': round(max(360, max_y + 100), 2),
        }

    node_by_id = {node.get('id'): node for node in nodes}
    levels = {node_id: 0 for node_id in node_by_id}
    for _ in range(len(nodes) + len(edges) + 1):
        changed = False
        for edge in edges:
            source = edge.get('from')
            target = edge.get('to')
            if source in levels and target in levels and levels[target] <= levels[source]:
                levels[target] = levels[source] + 1
                changed = True
        if not changed:
            break

    level_groups = {}
    for node in nodes:
        node_id = node.get('id')
        level_groups.setdefault(levels.get(node_id, 0), []).append(node)

    x_gap = 320
    y_gap = 190
    margin_x = 90
    margin_y = 70
    node_width = 180
    max_rows = max(len(group) for group in level_groups.values())
    canvas_height = max(240, margin_y * 2 + max_rows * y_gap)
    canvas_mid_y = canvas_height / 2
    positioned = {}
    layout_nodes = []

    for level in sorted(level_groups):
        group = level_groups[level]
        for index, node in enumerate(group):
            node_id = node.get('id')
            y_offset = (index - (len(group) - 1) / 2) * y_gap
            node_type = node.get('type') or 'task'
            label = node.get('label') or node_id
            width, height = get_bpmn_node_size(node_type, label)
            label_lines = wrap_bpmn_label(label, width, node_type)
            center_x = margin_x + level * x_gap
            center_y = canvas_mid_y + y_offset
            item = {
                'id': node_id,
                'type': node_type,
                'label': label,
                'label_lines': label_lines,
                'label_start_dy': round(-((len(label_lines) - 1) * 14) / 2, 2),
                'subprocess_id': node.get('subprocess_id'),
                'risk_score': node.get('risk_score'),
                'risk_category': node.get('risk_category'),
                'risk_class': node.get('risk_class') or 'none',
                'x': round(center_x - width / 2, 2),
                'y': round(center_y - height / 2, 2),
                'cx': round(center_x, 2),
                'cy': round(center_y, 2),
                'width': width,
                'height': height,
            }
            positioned[node_id] = item
            layout_nodes.append(item)

    layout_edges = []
    for edge in edges:
        source = positioned.get(edge.get('from'))
        target = positioned.get(edge.get('to'))
        if not source or not target:
            continue
        route = build_bpmn_edge_route(source, target)
        layout_edges.append({
            'from': edge.get('from'),
            'to': edge.get('to'),
            'label': edge.get('label') or edge_labels.get((edge.get('from'), edge.get('to'))),
            'path': route['path'],
            'label_x': route['label_x'],
            'label_y': route['label_y'],
        })

    width = margin_x * 2 + max(level_groups.keys()) * x_gap + node_width
    return {
        'nodes': layout_nodes,
        'edges': layout_edges,
        'width': round(width, 2),
        'height': round(canvas_height, 2),
    }

def build_bpmn_edge_route(source, target):
    dx = target['cx'] - source['cx']
    dy = target['cy'] - source['cy']

    if abs(dx) >= abs(dy):
        if dx >= 0:
            start_x = source['x'] + source['width']
            end_x = target['x']
        else:
            start_x = source['x']
            end_x = target['x'] + target['width']
        start_y = source['cy']
        end_y = target['cy']
        control_offset = max(70, abs(end_x - start_x) / 2)
        direction = 1 if dx >= 0 else -1
        c1x = start_x + control_offset * direction
        c1y = start_y
        c2x = end_x - control_offset * direction
        c2y = end_y
    else:
        if dy >= 0:
            start_y = source['y'] + source['height']
            end_y = target['y']
        else:
            start_y = source['y']
            end_y = target['y'] + target['height']
        start_x = source['cx']
        end_x = target['cx']
        control_offset = max(70, abs(end_y - start_y) / 2)
        direction = 1 if dy >= 0 else -1
        c1x = start_x
        c1y = start_y + control_offset * direction
        c2x = end_x
        c2y = end_y - control_offset * direction

    return {
        'path': f"M {round(start_x, 2)} {round(start_y, 2)} C {round(c1x, 2)} {round(c1y, 2)}, {round(c2x, 2)} {round(c2y, 2)}, {round(end_x, 2)} {round(end_y, 2)}",
        'label_x': round((start_x + end_x) / 2, 2),
        'label_y': round((start_y + end_y) / 2 - 8, 2),
    }

def generate_process_heatmap(process_name, risks):
    if not risks:
        return None
    labels = [risk['subprocess_name'] or risk['risk_description'] or f"Risk {risk['id']}" for risk in risks]
    data = np.array([[risk['initial_risk'], risk['residual_risk']] for risk in risks])
    filename = f"process_heatmap_{uuid.uuid4()}.png"
    colors = ['#4CAF50', '#FFC107', '#F44336']
    boundaries = [0.0, 3.9, 6.9, 9.0]
    cmap = ListedColormap(colors)
    norm = BoundaryNorm(boundaries, cmap.N, clip=True)

    height = max(4, min(10, len(labels) * 0.7))
    plt.figure(figsize=(9, height))
    sns.heatmap(data, xticklabels=['Initial risk', 'Residual risk'], yticklabels=labels, annot=True, cmap=cmap, norm=norm, cbar=False)
    plt.title(f"Heatmap процессных рисков: {process_name}")
    plt.tight_layout()
    plt.savefig(os.path.join("static", filename))
    plt.close()
    return filename

def build_process_report(process_id):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT p.id, p.company_id, p.name, p.description, p.process_type, p.owner, p.input_data,
                   p.output_data, p.regulations, p.resources, c.name, c.industry
            FROM processes p
            JOIN companies c ON c.id = p.company_id
            WHERE p.id = ?
        ''', (process_id,))
        process = cursor.fetchone()
        if not process:
            return None

        cursor.execute('''
            SELECT id, name, description, input_data, output_data, responsible_person, used_systems, order_index
            FROM subprocesses
            WHERE process_id = ?
            ORDER BY COALESCE(order_index, 9999), id
        ''', (process_id,))
        subprocesses = cursor.fetchall()

        cursor.execute('''
            SELECT pa.id, a.id, a.name, pa.role_in_process,
                   a.life_health, a.economy, a.ecology, a.dependency, a.social, a.international, a.threat_probability
            FROM process_assets pa
            JOIN assets a ON a.id = pa.asset_id
            WHERE pa.process_id = ?
            ORDER BY a.name
        ''', (process_id,))
        assets = cursor.fetchall()

        cursor.execute('SELECT id, bpmn_json, bpmn_xml, created_at FROM process_bpmn WHERE process_id = ? ORDER BY id DESC LIMIT 1', (process_id,))
        bpmn = cursor.fetchone()
        bpmn_subprocess_risks = get_bpmn_subprocess_risk_summary(cursor, process_id)

        cursor.execute('''
            SELECT pr.id, pr.process_id, pr.subprocess_id, sp.name, pr.asset_id, a.name,
                   pr.threat_id, t.name, pr.vulnerability_id, v.name, v.category,
                   pr.control_measure_id, cm.name, pr.risk_description,
                   pr.probability, pr.vulnerability_level, pr.impact, pr.initial_risk, pr.control_effectiveness,
                   pr.residual_risk, pr.risk_level, COALESCE(pr.risk_category, pr.risk_level), pr.cost,
                   pr.risk_reduction, pr.priority, pr.ai_recommendation
            FROM process_risks pr
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            LEFT JOIN assets a ON a.id = pr.asset_id
            LEFT JOIN threats t ON t.id = pr.threat_id
            LEFT JOIN vulnerabilities v ON v.id = pr.vulnerability_id
            LEFT JOIN control_measures cm ON cm.id = pr.control_measure_id
            WHERE pr.process_id = ?
            ORDER BY pr.residual_risk DESC
        ''', (process_id,))
        risk_rows = cursor.fetchall()

        cursor.execute('''
            SELECT rta.id, rta.title, rta.description, COALESCE(rta.status, 'Planned'),
                   rta.owner, rta.due_date, COALESCE(rta.progress, 0),
                   pr.risk_description, sp.name
            FROM risk_treatment_actions rta
            JOIN process_risks pr ON pr.id = rta.process_risk_id
            LEFT JOIN subprocesses sp ON sp.id = pr.subprocess_id
            WHERE pr.process_id = ?
            ORDER BY
                CASE WHEN rta.due_date IS NULL OR rta.due_date = '' THEN 1 ELSE 0 END,
                rta.due_date ASC,
                rta.id DESC
        ''', (process_id,))
        treatment_rows = cursor.fetchall()

    risks = []
    for row in risk_rows:
        risks.append({
            'id': row[0],
            'subprocess_name': row[3],
            'asset_name': row[5],
            'threat_name': row[7],
            'vulnerability_name': row[9],
            'vulnerability_category': row[10],
            'control_name': row[12],
            'risk_description': row[13],
            'probability': row[14] or 0,
            'vulnerability_level': row[15] or 0,
            'impact': row[16] or 0,
            'initial_risk': row[17] or 0,
            'control_effectiveness': row[18] or 0,
            'residual_risk': row[19] or 0,
            'numeric_risk_level': row[20] or 0,
            'risk_level': row[21] or '',
            'cost': row[22] or 0,
            'risk_reduction': row[23] or 0,
            'priority': row[24] or '',
            'ai_recommendation': row[25] or '',
        })

    residuals = [risk['residual_risk'] for risk in risks]
    high_count = sum(1 for risk in risks if risk['risk_level'] == 'Высокий')
    medium_count = sum(1 for risk in risks if risk['risk_level'] == 'Средний')
    low_count = sum(1 for risk in risks if risk['risk_level'] == 'Низкий')
    summary = {
        'risk_count': len(risks),
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'max_residual_risk': round(max(residuals), 2) if residuals else 0,
        'avg_residual_risk': round(sum(residuals) / len(residuals), 2) if residuals else 0,
    }
    if high_count:
        summary['conclusion'] = 'Процесс содержит высокие остаточные риски и требует приоритетного плана снижения.'
    elif medium_count:
        summary['conclusion'] = 'Процесс имеет средние риски; требуется мониторинг и точечное усиление контролей.'
    elif risks:
        summary['conclusion'] = 'Остаточные риски процесса находятся на допустимом уровне при сохранении текущих контролей.'
    else:
        summary['conclusion'] = 'Для процесса пока не добавлены риски; отчет неполный.'

    bpmn_model = enrich_bpmn_model_with_risks(parse_bpmn_json(bpmn[1] if bpmn else None), bpmn_subprocess_risks)
    bpmn_quality = build_bpmn_quality_summary(bpmn_model, subprocesses)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        bpmn_business_context = build_bpmn_business_context(cursor, process_id, bpmn_model)

    return {
        'process': process,
        'subprocesses': subprocesses,
        'assets': assets,
        'bpmn': bpmn,
        'bpmn_model': bpmn_model,
        'bpmn_subprocess_risks': bpmn_subprocess_risks,
        'bpmn_business_context': bpmn_business_context,
        'risks': risks,
        'treatments': treatment_rows,
        'summary': summary,
        'bpmn_quality': bpmn_quality,
        'heatmap': generate_process_heatmap(process[2], risks),
    }

@app.route('/process_report/<int:process_id>')
@login_required
def process_report(process_id):
    report = build_process_report(process_id)
    if not report:
        flash('Процесс не найден!')
        return redirect(url_for('list_processes'))
    return render_template('process_report.html', **report)


@app.route('/ai_analysis/<int:process_id>')
@login_required
def ai_analysis(process_id):
    report = build_process_report(process_id)
    if not report:
        flash('Процесс не найден!')
        return redirect(url_for('list_processes'))
    analysis = analyze_process_risks(report['risks'])
    return render_template('ai_analysis.html', process=report['process'], risks=report['risks'], summary=report['summary'], analysis=analysis)



if __name__ == '__main__':
    app.run(debug=True)
