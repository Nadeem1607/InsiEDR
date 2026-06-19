import csv
import json
import random
import uuid
from datetime import datetime, timedelta

start_date = datetime(2026, 5, 15)
end_date = datetime(2026, 6, 13, 23, 59, 59)

# We want roughly 30,000 events overall, ~1000 per day.
TOTAL_DAYS = (end_date - start_date).days + 1
EVENTS_PER_DAY = 1000

# Distribution probabilities
# Info: 60%, Low: 25%, Medium: 10%, High: 4%, Critical: 1%
PROBS = {
    'Info': 0.60,
    'Low': 0.25,
    'Medium': 0.10,
    'High': 0.04,
    'Critical': 0.01
}

USERS = [
    {"username": "asmith", "agent_id": "AG-1001"},
    {"username": "bjones", "agent_id": "AG-1002"},
    {"username": "cwilliams", "agent_id": "AG-1003"},
    {"username": "dbrown", "agent_id": "AG-1004"},
    {"username": "ejohnson", "agent_id": "AG-1005"},
    {"username": "flee", "agent_id": "AG-1006"},
    {"username": "gwhite", "agent_id": "AG-1007"},
    {"username": "hharris", "agent_id": "AG-1008"},
    {"username": "imartin", "agent_id": "AG-1009"},
    {"username": "jthompson", "agent_id": "AG-1010"},
]

SCENARIOS = {
    'Info': [
        ("Normal user login", {"logon_risk": 5, "file_risk": 0, "device_risk": 0, "http_risk": 0, "heuristics": {"detections": []}}),
        ("Standard file access", {"logon_risk": 0, "file_risk": 5, "device_risk": 0, "http_risk": 0, "heuristics": {"detections": []}}),
        ("Intranet browsing", {"logon_risk": 0, "file_risk": 0, "device_risk": 0, "http_risk": 5, "heuristics": {"detections": []}}),
    ],
    'Low': [
        ("After-hours login", {"logon_risk": 25, "file_risk": 0, "device_risk": 0, "http_risk": 0, "heuristics": {"detections": [{"scenario": "After-hours login"}]}}),
        ("Small USB transfer", {"logon_risk": 0, "file_risk": 20, "device_risk": 25, "http_risk": 0, "heuristics": {"detections": [{"scenario": "Routine USB usage"}]}}),
        ("Job search site visit", {"logon_risk": 0, "file_risk": 0, "device_risk": 0, "http_risk": 30, "heuristics": {"detections": [{"scenario": "Job search browsing"}]}}),
    ],
    'Medium': [
        ("Multiple failed logins", {"logon_risk": 50, "file_risk": 0, "device_risk": 0, "http_risk": 0, "heuristics": {"detections": [{"scenario": "Failed login spike"}]}}),
        ("Large USB transfer", {"logon_risk": 0, "file_risk": 40, "device_risk": 55, "http_risk": 0, "heuristics": {"detections": [{"scenario": "Large data transfer via USB"}]}}),
        ("Accessing known file-sharing site", {"logon_risk": 0, "file_risk": 10, "device_risk": 0, "http_risk": 60, "heuristics": {"detections": [{"scenario": "File-sharing site visit"}]}}),
        ("Weekend remote RDP login", {"logon_risk": 60, "file_risk": 0, "device_risk": 0, "http_risk": 0, "heuristics": {"detections": [{"scenario": "Weekend RDP access"}]}}),
    ],
    'High': [
        ("Sensitive file access + large USB copy", {"logon_risk": 0, "file_risk": 75, "device_risk": 80, "http_risk": 0, "heuristics": {"detections": [{"scenario": "Potential career-jump IP theft"}]}}),
        ("Mass file deletion", {"logon_risk": 0, "file_risk": 85, "device_risk": 0, "http_risk": 0, "heuristics": {"detections": [{"scenario": "Mass file deletion detected"}]}}),
        ("Suspicious domain access + large file open", {"logon_risk": 0, "file_risk": 50, "device_risk": 0, "http_risk": 80, "heuristics": {"detections": [{"scenario": "Suspicious web traffic"}]}}),
    ],
    'Critical': [
        ("WikiLeaks-style exfiltration", {"logon_risk": 90, "file_risk": 95, "device_risk": 98, "http_risk": 85, "predicted_scenario": {"scenario": "WikiLeaks-style exfiltration"}}),
        ("Admin betrayal / IT sabotage", {"logon_risk": 95, "file_risk": 98, "device_risk": 0, "http_risk": 10, "predicted_scenario": {"scenario": "IT sabotage / Mass deletion"}}),
        ("Restricted file browsing + Dropbox upload", {"logon_risk": 10, "file_risk": 92, "device_risk": 0, "http_risk": 95, "predicted_scenario": {"scenario": "Restricted file exfiltration via Cloud"}}),
    ]
}

def get_score_for_level(level):
    if level == 'Info':
        return random.uniform(0, 15)
    elif level == 'Low':
        return random.uniform(15, 35)
    elif level == 'Medium':
        return random.uniform(35, 65)
    elif level == 'High':
        return random.uniform(65, 85)
    else:
        return random.uniform(85, 100)

events = []

def generate_events():
    global events
    current_time = start_date
    levels = list(PROBS.keys())
    weights = list(PROBS.values())
    
    event_id = 1
    
    while current_time <= end_date:
        for _ in range(EVENTS_PER_DAY):
            # random time within the day
            ev_time = current_time + timedelta(seconds=random.randint(0, 86399))
            
            level = random.choices(levels, weights=weights, k=1)[0]
            user = random.choice(USERS)
            scenario, signals = random.choice(SCENARIOS[level])
            score = get_score_for_level(level)
            
            events.append({
                "payload_id": str(uuid.uuid4()),
                "agent_id": user["agent_id"],
                "username": user["username"],
                "risk_score": round(score, 2),
                "risk_level": level,
                "correlated_signals_json": json.dumps(signals),
                "summary": scenario,
                "created_at": ev_time.strftime("%Y-%m-%d %H:%M:%S")
            })
            event_id += 1
            
        current_time += timedelta(days=1)

generate_events()

# Sort events by created_at
events.sort(key=lambda x: x["created_at"])

filename = "d:/Projects/AISH/InsiEDR/risk_events_dataset.csv"
with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = ["payload_id", "agent_id", "username", "risk_score", "risk_level", "correlated_signals_json", "summary", "created_at"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
    writer.writeheader()
    for ev in events:
        writer.writerow(ev)

# Validation Reporting
stats = { 'Info': 0, 'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0 }
total = len(events)
for ev in events:
    stats[ev['risk_level']] += 1

print(f"Generated {total} events.")
print("Severity Distribution:")
for level, count in stats.items():
    print(f"  {level}: {count} ({count/total*100:.2f}%)")

print(f"\nDataset written to {filename}")
