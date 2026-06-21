def recommend_process_risk(residual_risk, control_effectiveness=None, control_measure_id=None, risk_level=None, vulnerability_level=None):
    effectiveness = control_effectiveness if control_effectiveness is not None else 0
    recommendations = []

    if residual_risk > 7:
        recommendations.append("High priority mitigation required.")
    if not control_measure_id:
        recommendations.append("Add control measure. Необходимо назначить контрольную меру для подпроцесса.")
    if vulnerability_level is not None and vulnerability_level >= 3:
        recommendations.append("Fix vulnerability urgently. Высокая уязвимость: требуется срочно устранить или снизить vulnerability level.")
    if effectiveness < 0.3 and residual_risk > 6.9:
        recommendations.append("Требуется усиление контроля: остаточный риск высокий, эффективность защиты низкая.")
    if risk_level == "Высокий":
        recommendations.append("Риск требует приоритетного устранения и контроля сроков выполнения мер.")
    elif risk_level == "Средний":
        recommendations.append("Риск требует плана снижения и регулярного мониторинга.")
    else:
        recommendations.append("Риск допустим при сохранении текущих мер контроля.")

    return " ".join(recommendations)


def analyze_process_risks(risks):
    if not risks:
        return {
            "score": 0,
            "rating": "No data",
            "summary": "Для процесса пока нет данных о рисках.",
            "top_risk": None,
            "weak_control_risks": [],
            "missing_control_risks": [],
            "repeated_threats": [],
            "repeated_vulnerabilities": [],
            "priority_actions": ["Добавить риски по ключевым подпроцессам."],
        }

    max_residual = max(risk["residual_risk"] for risk in risks)
    avg_residual = sum(risk["residual_risk"] for risk in risks) / len(risks)
    high_count = sum(1 for risk in risks if risk["risk_level"] == "Высокий")
    score = round((max_residual * 0.65) + (avg_residual * 0.25) + min(high_count, 3) * 0.3, 2)
    score = min(score, 9)

    if score >= 7:
        rating = "Critical"
    elif score >= 5:
        rating = "High"
    elif score >= 3:
        rating = "Medium"
    else:
        rating = "Low"

    top_risk = max(risks, key=lambda risk: risk["residual_risk"])
    weak_control_risks = [
        risk for risk in risks
        if risk["control_effectiveness"] < 0.3 and risk["residual_risk"] >= 4
    ]
    missing_control_risks = [
        risk for risk in risks
        if not risk.get("control_name")
    ]

    repeated_threats = collect_repeated_values(risks, "threat_name")
    repeated_vulnerabilities = collect_repeated_values(risks, "vulnerability_name")

    priority_actions = []
    if top_risk:
        priority_actions.append(
            f"В первую очередь снизить риск подпроцесса \"{top_risk.get('subprocess_name') or 'без названия'}\"."
        )
    if missing_control_risks:
        priority_actions.append("Назначить контрольные меры для рисков без контроля.")
    if weak_control_risks:
        priority_actions.append("Усилить контрольные меры с эффективностью ниже 0.30.")
    if repeated_threats:
        priority_actions.append("Проверить повторяющиеся угрозы и закрыть их единым планом мер.")
    if not priority_actions:
        priority_actions.append("Поддерживать текущие контроли и периодически пересматривать оценки.")

    summary = (
        f"Уровень внимания к процессу: {rating}. "
        f"Максимальная оценка пробела: {round(max_residual, 2)}, средняя оценка: {round(avg_residual, 2)}. "
        f"Критичных пробелов: {high_count}."
    )

    return {
        "score": score,
        "rating": rating,
        "summary": summary,
        "top_risk": top_risk,
        "weak_control_risks": weak_control_risks,
        "missing_control_risks": missing_control_risks,
        "repeated_threats": repeated_threats,
        "repeated_vulnerabilities": repeated_vulnerabilities,
        "priority_actions": priority_actions,
    }


def collect_repeated_values(risks, key):
    counts = {}
    for risk in risks:
        value = risk.get(key)
        if not value:
            continue
        counts[value] = counts.get(value, 0) + 1
    return [
        {"name": name, "count": count}
        for name, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)
        if count > 1
    ]
