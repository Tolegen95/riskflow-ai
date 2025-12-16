import sqlite3

# Список мер контроля для вставки
control_measures = [
    "A.5.1.1 Policies for information Security",
    "A.5.1.2 Review of the policies for information security",
    "A.6.1.1 Information security roles and responsibilities",
    "A.6.1.2 Segregation of duties",
    "A.6.1.3 Contact with authorities",
    "A.6.1.4 Contact with special interest groups",
    "A.6.1.5 Information security in project management",
    "A.6.2.1 Mobile device policy",
    "A.6.2.2 Teleworking",
    "A.7.1.1 Screening",
    "A.7.1.2 Terms and conditions of employment",
    "A.7.2.1 Management responsibilities",
    "A.7.2.2 Information security awareness, education and training",
    "A.7.2.3 Disciplinary process",
    "A.7.3.1 Termination or change of employment responsibilities",
    "A.8.1.1 Inventory of assets",
    "A.8.1.2 Ownership of assets",
    "A.8.1.3 Acceptable use of assets",
    "A.8.1.4 Return of assets",
    "A.8.2.1 Classification of information",
    "A.8.2.2 Labelling of information",
    "A.8.2.3 Handling of assets",
    "A.8.3.1 Management of removable media",
    "A.8.3.2 Disposal of media",
    "A.8.3.3 Physical media transfer",
    "A.9.1.1 Access control policy",
    "A.9.1.2 Access to networks and network services",
    "A.9.2.1 User registration and de-registration",
    "A.9.2.2 User access provisioning",
    "A.9.2.3 Management of privileged access rights",
    "A.9.2.4 Management of secret authentication information of users",
    "A.9.2.5 Review of user access rights",
    "A.9.2.6 Removal or adjustment of access rights",
    "A.9.3.1 Use of secret authentication information",
    "A.9.4.1 Information access restriction",
    "A.9.4.2 Secure log-on procedures",
    "A.9.4.3 Password management system",
    "A.9.4.4 Use of privileged utility programs",
    "A.9.4.5 Access control to program source code",
    "A.10.1.1 Policy on the use of cryptographic controls",
    "A.10.1.2 Key management",
    "A.11.1.1 Physical security Perimeter",
    "A.11.1.2 Physical entry controls",
    "A.11.1.3 Securing offices, rooms and facilities",
    "A.11.1.4 Protecting against external and environmental threats",
    "A.11.1.5 Working in secure areas",
    "A.11.1.6 Delivery and loading areas",
    "A.11.2.1 Equipment siting and Protection",
    "A.11.2.2 Supporting utilities",
    "A.11.2.3 Cabling security",
    "A.11.2.4 Equipment maintenance",
    "A.11.2.5 Removal of assets",
    "A.11.2.6 Security of equipment and assets off-premises",
    "A.11.2.7 Secure disposal or reuse of equipment",
    "A.11.2.8 Unattended user equipment",
    "A.11.2.9 Clear desk and clear screen policy",
    "A.12.1.1 Documented operating procedures",
    "A.12.1.2 Change management",
    "A.12.1.3 Capacity management",
    "A.12.1.4 Separation of development, testing and operational environments",
    "A.12.2.1 Controls against malware",
    "A.12.3.1 Information backup",
    "A.12.4.1 Event logging",
    "A.12.4.2 Protection of log information",
    "A.12.4.3 Administrator and operator logs",
    "A.12.4.4 Clock synchronization",
    "A.12.5.1 Installation of software on operational systems",
    "A.12.6.1 Management of technical vulnerabilities",
    "A.12.6.2 Restrictions on software installation",
    "A.12.7.1 Information systems audit controls",
    "A.13.1.1 Network control",
    "A.13.1.2 Security of network",
    "A.13.1.3 Segregation in networks",
    "A.13.2.1 Information transfer policies and procedures",
    "A.13.2.2 Agreements on information transfer",
    "A.13.2.3 Electronic messaging",
    "A.13.2.4 Confidentiality or non-disclosure agreements",
    "A.14.1.1 Information security requirements analysis and specification",
    "A.14.1.2 Securing application services on public networks",
    "A.14.1.3 Protecting application services transactions",
    "A.14.2.1 Secure development policy",
    "A.14.2.2 System change control procedures",
    "A.14.2.3 Technical review of applications after operating platform changes",
    "A.14.2.4 Restrictions on changes to software packages",
    "A.14.2.5 Restrictions on changes to software packages",
    "A.14.2.6 Secure development environment",
    "A.14.2.7 Outsourced development",
    "A.14.2.8 System security testing",
    "A.14.2.9 System acceptance testing",
    "A.14.3.1 Protection of test data",
    "A.15.1.1 Information security policy for supplier relationships",
    "A.15.1.2 Addressing security within supplier agreements",
    "A.15.1.3 Information and communication technology supply chain",
    "A.15.2.1 Monitoring and review of supplier services",
    "A.15.2.2 Managing changes to supplier services",
    "A.16.1.1 Responsibilities and procedures",
    "A.16.1.2 Reporting information security events",
    "A.16.1.3 Reporting information security weaknesses",
    "A.16.1.4 Assessment of and decision on information security events",
    "A.16.1.5 Response to information security incidents",
    "A.16.1.6 Learning from information security incidents",
    "A.16.1.7 Collection of evidence",
    "A.17.1.1 Planning information security continuity",
    "A.17.1.2 Implementing information security continuity",
    "A.17.1.3 Verify, review and evaluate information security continuity",
    "A.17.2.1 Availability of information processing facilities",
    "A.18.1.1 Identification of applicable legislation and contractual requirements",
    "A.18.1.2 Intellectual property rights",
    "A.18.1.3 Protection of records",
    "A.18.1.4 Privacy and protection of personally identifiable information",
    "A.18.1.5 Regulation of cryptographic controls",
    "A.18.2.1 Independent review of information security",
    "A.18.2.2 Compliance with security policies and standards",
    "A.18.2.3 Technical compliance review"
]

def populate_control_measures():
    # Подключение к базе данных
    with sqlite3.connect('risk_assessment.db') as conn:
        cursor = conn.cursor()
        
        # Проверка наличия таблицы control_measures
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='control_measures'")
        if not cursor.fetchone():
            print("Ошибка: таблица 'control_measures' не существует в базе данных.")
            return
        
        # Подсчёт существующих мер контроля
        cursor.execute('SELECT COUNT(*) FROM control_measures')
        initial_count = cursor.fetchone()[0]
        print(f"Мер контроля в базе до вставки: {initial_count}")
        
        # Вставка мер контроля
        inserted = 0
        skipped = 0
        for measure in control_measures:
            try:
                cursor.execute('INSERT INTO control_measures (name) VALUES (?)', (measure,))
                inserted += 1
            except sqlite3.IntegrityError:
                # Пропускаем, если мера контроля уже существует (UNIQUE constraint)
                skipped += 1
        
        # Подтверждение изменений
        conn.commit()
        
        # Подсчёт мер контроля после вставки
        cursor.execute('SELECT COUNT(*) FROM control_measures')
        final_count = cursor.fetchone()[0]
        print(f"Мер контроля в базе после вставки: {final_count}")
        print(f"Добавлено мер контроля: {inserted}")
        print(f"Пропущено (уже существуют): {skipped}")

if __name__ == "__main__":
    populate_control_measures()