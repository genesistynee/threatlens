import json
import html
import webbrowser
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer

from services.investigation import load_events, run_investigation
from services.incident import build_incident
from services.timeline import build_attack_timeline
from services.evidence import build_evidence_map
from services.alert import build_critical_alert


SCENARIOS = [
    "clean",
    "obvious_attack",
    "noisy_attack",
]


def analyse_scenario(scenario):
    events = load_events(scenario)
    findings = run_investigation(events)
    incident = build_incident(events, findings)
    timeline = build_attack_timeline(events, findings)
    evidence = build_evidence_map(events, findings)
    alert = build_critical_alert(findings)

    return {
        "scenario": scenario,
        "event_count": len(events),
        "finding_count": len(findings),
        "incident": incident,
        "timeline": timeline,
        "evidence": evidence,
        "alert": alert,
        "events": events,
    }


def make_data():
    return {
        scenario: analyse_scenario(scenario)
        for scenario in SCENARIOS
    }


def esc(value):
    return html.escape(str(value))


def build_html(data):
    data_json = json.dumps(data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>ThreatLens</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    font-family: Arial, Helvetica, sans-serif;
    background: #0b1020;
    color: #e8edf7;
}}

.header {{
    padding: 28px 40px;
    border-bottom: 1px solid #26304a;
    background: #0f1629;
}}

.logo {{
    font-size: 28px;
    font-weight: 800;
    letter-spacing: 1px;
}}

.subtitle {{
    color: #8d9ab5;
    margin-top: 6px;
}}

.container {{
    max-width: 1400px;
    margin: auto;
    padding: 30px 40px;
}}

.controls {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 25px;
    gap: 20px;
}}

select {{
    background: #151e34;
    color: white;
    border: 1px solid #34415f;
    border-radius: 8px;
    padding: 11px 14px;
    font-size: 15px;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
    margin-bottom: 25px;
}}

.card {{
    background: #11192d;
    border: 1px solid #273452;
    border-radius: 12px;
    padding: 20px;
}}

.card-title {{
    color: #8997b4;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}

.card-value {{
    font-size: 28px;
    font-weight: 700;
    margin-top: 10px;
}}

.critical {{
    color: #ff5c6c;
}}

.high {{
    color: #ffb454;
}}

.normal {{
    color: #63d7a3;
}}

.section {{
    background: #11192d;
    border: 1px solid #273452;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 22px;
}}

.section h2 {{
    margin-top: 0;
    font-size: 19px;
}}

.timeline {{
    border-left: 2px solid #394865;
    margin-left: 10px;
    padding-left: 25px;
}}

.timeline-item {{
    position: relative;
    margin-bottom: 25px;
}}

.timeline-item::before {{
    content: "";
    position: absolute;
    width: 11px;
    height: 11px;
    background: #65a9ff;
    border-radius: 50%;
    left: -32px;
    top: 5px;
}}

.stage {{
    font-weight: 700;
    font-size: 16px;
}}

.time {{
    color: #7786a4;
    font-size: 13px;
    margin: 5px 0;
}}

.reason {{
    color: #b5bfd2;
    line-height: 1.5;
}}

.badge {{
    display: inline-block;
    padding: 5px 9px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 700;
    background: #202c47;
    color: #a9c8ff;
}}

.evidence {{
    display: grid;
    gap: 10px;
}}

.evidence-row {{
    display: grid;
    grid-template-columns: 260px 1fr;
    padding: 13px;
    background: #0d1527;
    border-radius: 8px;
    border: 1px solid #202b43;
}}

.event-id {{
    font-family: monospace;
    color: #79b5ff;
}}

.event-details {{
    color: #c1c9d9;
}}

.alert {{
    border: 1px solid #a63c49;
    background: #29151b;
}}

.alert h2 {{
    color: #ff6877;
}}

.attack-chain {{
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
}}

.chain-stage {{
    padding: 13px 16px;
    border: 1px solid #385072;
    border-radius: 8px;
    background: #16223a;
}}

.arrow {{
    color: #687895;
    font-size: 20px;
}}

.entities {{
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}}

.entity {{
    background: #17233b;
    border: 1px solid #2d4163;
    padding: 9px 12px;
    border-radius: 7px;
    font-family: monospace;
}}

.empty {{
    color: #7f8ba4;
    padding: 10px 0;
}}

.footer {{
    text-align: center;
    color: #65718b;
    padding: 30px;
}}

@media(max-width: 900px) {{
    .grid {{
        grid-template-columns: repeat(2, 1fr);
    }}

    .container {{
        padding: 20px;
    }}
}}

</style>
</head>

<body>

<div class="header">
    <div class="logo">THREATLENS</div>
    <div class="subtitle">
        Evidence-Based Cyber Threat Intelligence & Attack Reconstruction
    </div>
</div>

<div class="container">

    <div class="controls">
        <div>
            <strong>Investigation Scenario</strong>
        </div>

        <select id="scenarioSelect" onchange="renderScenario()">
            <option value="clean">Clean Logs</option>
            <option value="obvious_attack">Obvious Attack</option>
            <option value="noisy_attack" selected>Noisy Attack</option>
        </select>
    </div>

    <div id="dashboard"></div>

</div>

<div class="footer">
    ThreatLens • Internal Hackathon Prototype
</div>

<script>

const DATA = {data_json};

function esc(value) {{
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
}}

function renderScenario() {{

    const scenario =
        document.getElementById("scenarioSelect").value;

    const data = DATA[scenario];

    const incident = data.incident;
    const alert = data.alert;

    let severity = incident
        ? incident.severity
        : "NORMAL";

    let severityClass =
        severity.toLowerCase();

    let html = "";

    html += `
        <div class="grid">

            <div class="card">
                <div class="card-title">Events Processed</div>
                <div class="card-value">
                    ${{data.event_count}}
                </div>
            </div>

            <div class="card">
                <div class="card-title">Security Findings</div>
                <div class="card-value">
                    ${{data.finding_count}}
                </div>
            </div>

            <div class="card">
                <div class="card-title">Risk Score</div>
                <div class="card-value ${{severityClass}}">
                    ${{incident ? incident.risk_score : 0}}
                </div>
            </div>

            <div class="card">
                <div class="card-title">Severity</div>
                <div class="card-value ${{severityClass}}">
                    ${{severity}}
                </div>
            </div>

        </div>
    `;

    if (alert.alert) {{

        html += `
            <div class="section alert">

                <h2>🚨 SPECIAL SECURITY ALERT</h2>

                <p>
                    <span class="badge">
                        ${{esc(alert.level)}}
                    </span>
                </p>

                <h3>${{esc(alert.title)}}</h3>

                <p>
                    ${{esc(alert.reason)}}
                </p>

                <h3>Attack Chain</h3>

                <div class="attack-chain">

                    ${{alert.stages.map((stage, index) => `

                        <div class="chain-stage">
                            ${{esc(stage)}}
                        </div>

                        ${{index < alert.stages.length - 1
                            ? '<div class="arrow">→</div>'
                            : ''
                        }}

                    `).join("")}}

                </div>

            </div>
        `;

    }} else {{

        html += `
            <div class="section">

                <h2>✅ No Critical Alert</h2>

                <p>
                    ThreatLens did not establish a sufficiently
                    strong multi-stage attack chain.
                </p>

            </div>
        `;
    }}

    if (incident) {{

        html += `
            <div class="section">

                <h2>Incident Overview</h2>

                <div class="entities">

                    <div class="entity">
                        Incident: ${{esc(incident.incident_id)}}
                    </div>

                    ${{incident.users.map(user => `
                        <div class="entity">
                            User: ${{esc(user)}}
                        </div>
                    `).join("")}}

                    ${{incident.devices.map(device => `
                        <div class="entity">
                            Device: ${{esc(device)}}
                        </div>
                    `).join("")}}

                </div>

            </div>
        `;

    }}

    html += `
        <div class="section">

            <h2>📅 Attack Timeline</h2>

            <div class="timeline">

                ${{data.timeline.length
                    ? data.timeline.map(step => `

                        <div class="timeline-item">

                            <div class="stage">
                                ${{esc(step.stage)}}
                            </div>

                            <div class="time">
                                ${{esc(step.timestamp)}}
                            </div>

                            <div>
                                <span class="badge">
                                    Evidence:
                                    ${{step.evidence_event_ids
                                        .map(esc)
                                        .join(", ")}}
                                </span>
                            </div>

                            <div class="reason">
                                ${{esc(step.reason)}}
                            </div>

                        </div>

                    `).join("")
                    : '<div class="empty">No attack timeline established.</div>'
                }}

            </div>

        </div>
    `;

    html += `
        <div class="section">

            <h2>🔬 Evidence Map</h2>

            <div class="evidence">

                ${{data.evidence.length
                    ? data.evidence.map(item => `

                        <div class="evidence-row">

                            <div>
                                <strong>
                                    ${{esc(item.stage)}}
                                </strong>
                            </div>

                            <div class="event-details">

                                <div>
                                    ${{item.evidence_event_ids
                                        .map(id => `
                                            <span class="event-id">
                                                ${{esc(id)}}
                                            </span>
                                        `)
                                        .join(" &nbsp; ")}}
                                </div>

                                <div style="margin-top:7px;">
                                    ${{esc(item.reason)}}
                                </div>

                            </div>

                        </div>

                    `).join("")
                    : '<div class="empty">No suspicious evidence.</div>'
                }}

            </div>

        </div>
    `;

    html += `
        <div class="section">

            <h2>🛡️ Investigation Summary</h2>

            <p>
                ThreatLens processed
                <strong>${{data.event_count}}</strong>
                events and generated
                <strong>${{data.finding_count}}</strong>
                security findings.
            </p>

            <p>
                Individual events are monitored continuously,
                but escalation occurs only when correlated
                evidence establishes a stronger attack chain.
            </p>

        </div>
    `;

    document.getElementById("dashboard").innerHTML = html;
}}

renderScenario();

</script>

</body>
</html>
"""


def main():
    print("Analysing scenarios...")

    data = make_data()

    html_content = build_html(data)

    output_file = Path(__file__).parent / "threatlens_dashboard.html"

    output_file.write_text(
        html_content,
        encoding="utf-8"
    )

    print()
    print("=" * 60)
    print("THREATLENS DASHBOARD")
    print("=" * 60)
    print()
    print(f"Dashboard created:")
    print(output_file)
    print()
    print("Opening browser...")

    webbrowser.open(output_file.as_uri())


if __name__ == "__main__":
    main()