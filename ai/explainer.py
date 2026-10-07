from ai.ollama_client import ask_ollama


PRIMARY_STAGES = {
    "Suspicious Authentication",
    "Privilege Escalation",
    "Sensitive Resource Access",
    "Potential Data Exfiltration",
}


def build_evidence_ids(finding):
    evidence_ids = []

    for key in [
        "event_id",
        "file_event_id",
        "usb_event_id",
        "transfer_event_id",
    ]:
        event_id = finding.get(key)

        if event_id and event_id not in evidence_ids:
            evidence_ids.append(event_id)

    return evidence_ids


def deterministic_explanation(finding):
    stage = finding.get("stage")
    reason = finding.get("reason")

    if stage == "Suspicious Authentication":
        return f"A suspicious authentication event was detected because {reason}"

    elif stage == "Privilege Escalation":
        return f"A privilege escalation event was detected because {reason}"

    elif stage == "Sensitive Resource Access":
        return f"A sensitive resource access event was detected because {reason}"

    elif stage == "Potential Data Exfiltration":
        return f"Potential data exfiltration was identified because {reason}"

    return reason or "No explanation available."


def explain_with_llm(finding):
    stage = finding.get("stage")
    reason = finding.get("reason")
    evidence_ids = build_evidence_ids(finding)

    prompt = f"""
Write ONE concise cybersecurity explanation for this VERIFIED finding.

Use ONLY the information provided.

Stage: {stage}
Evidence IDs: {", ".join(evidence_ids)}
Reason: {reason}

Rules:
- Maximum 40 words.
- Mention the evidence IDs.
- State the concrete events that support the stage.
- No advice.
- No recommendations.
- No speculation.
- Do not mention "detection engine".
- Do not say "further investigation".
- Do not add information.
- Output ONLY the explanation.
"""

    return ask_ollama(prompt)


def explain_findings(findings):
    """
    Explain verified ThreatLens findings.

    The LLM is used only as an explanation layer.
    Detection and correlation remain independent of the LLM.

    If the local LLM is unavailable, deterministic explanations
    are used as a fallback.
    """

    explanations = []

    for finding in findings:

        stage = finding.get("stage")

        if stage not in PRIMARY_STAGES:
            continue

        evidence_ids = build_evidence_ids(finding)

        try:
            explanation = explain_with_llm(finding)
            source = "local_llm"

        except Exception as error:

            print(
                f"\n[AI fallback] LLM unavailable for '{stage}': {error}"
            )

            explanation = deterministic_explanation(finding)
            source = "deterministic_fallback"

        explanations.append({
            "stage": stage,
            "evidence_event_ids": evidence_ids,
            "explanation": explanation,
            "source": source,
        })

    return explanations