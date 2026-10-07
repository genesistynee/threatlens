def calculate_risk(findings):
    """
    Calculate incident risk using the strongest evidence
    from each attack stage instead of double-counting
    overlapping findings.
    """

    risk_score = 0
    factors = []

    stages = {
        "Suspicious Authentication": 20,
        "Privilege Escalation": 20,
        "Sensitive Resource Access": 20,
        "Potential Data Exfiltration": 30
    }

    detected_stages = set()

    for finding in findings:
        stage = finding.get("stage")

        if stage in stages:
            detected_stages.add(stage)

    for stage, points in stages.items():

        if stage in detected_stages:
            risk_score += points
            factors.append(stage)

    # Bonus for demonstrating a multi-stage attack.
    if len(detected_stages) >= 3:
        risk_score += 10
        factors.append("Multiple attack stages occurred in sequence")

    if risk_score >= 75:
        severity = "Critical"
    elif risk_score >= 50:
        severity = "High"
    elif risk_score >= 25:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "factors": factors
    }