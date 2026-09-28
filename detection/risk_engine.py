def calculate_risk(
    severity,
    malicious=False,
    frequency=1
):

    score = 0

    reasons = []

    if severity == "critical":

        score += 40

        reasons.append(
            ("Critical Severity", 40)
        )

    elif severity == "high":

        score += 30

        reasons.append(
            ("High Severity", 30)
        )

    elif severity == "medium":

        score += 20

        reasons.append(
            ("Medium Severity", 20)
        )

    else:

        score += 10

        reasons.append(
            ("Low Severity", 10)
        )

    if malicious:

        score += 25

        reasons.append(
            ("Threat Intelligence Match", 25)
        )

    frequency_bonus = min(
        frequency * 5,
        20
    )

    score += frequency_bonus

    reasons.append(
        ("Attack Frequency", frequency_bonus)
    )

    return score, reasons