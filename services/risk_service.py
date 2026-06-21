def calculate_event_potentiality(probability, vulnerability_level):
    return max((probability or 0) + (vulnerability_level or 0) - 1, 0)


def calculate_process_risk_metrics(probability, vulnerability_level, impact, control_effectiveness=0, cost=0, asset_value=1):
    potentiality = calculate_event_potentiality(probability, vulnerability_level)
    risk_level = potentiality * (impact or 0)
    residual_risk = risk_level * (1 - (control_effectiveness or 0))
    risk_reduction = risk_level - residual_risk
    priority = calculate_priority(risk_reduction, asset_value, cost)
    return {
        "potentiality": potentiality,
        "risk_level": risk_level,
        "residual_risk": residual_risk,
        "risk_reduction": risk_reduction,
        "priority": priority,
    }


def calculate_priority(risk_reduction, asset_value=1, cost=0):
    value_score = 3 if (asset_value or 0) >= 7 else 2 if (asset_value or 0) >= 4 else 1
    reduction_score = 3 if (risk_reduction or 0) >= 5 else 2 if (risk_reduction or 0) >= 2 else 1
    cost_score = 3 if (cost or 0) <= 2 else 2 if (cost or 0) <= 5 else 1
    score = value_score + reduction_score + cost_score
    if score >= 8:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def classify_numeric_risk(risk_value):
    if (risk_value or 0) <= 3.9:
        return "Низкий"
    if risk_value <= 6.9:
        return "Средний"
    return "Высокий"
