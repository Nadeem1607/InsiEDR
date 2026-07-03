from heuristics.logon_rules import detect_logon_scenarios
from heuristics.file_rules import detect_file_scenarios
from heuristics.http_rules import detect_http_scenarios
from heuristics.device_rules import detect_device_scenarios


def calculate_overall_severity(score):

    if score >= 60:
        return "CRITICAL"

    if score >= 30:
        return "HIGH"

    if score >= 15:
        return "MEDIUM"

    return "LOW"


def detect_insider_threat(features):

    all_detections = []

    # ==========================================
    # Run Modules
    # ==========================================

    logon_results = detect_logon_scenarios(features)

    file_results = detect_file_scenarios(features)

    http_results = detect_http_scenarios(features)

    device_results = detect_device_scenarios(features)

    # ==========================================
    # Aggregate
    # ==========================================

    all_detections.extend(logon_results)
    all_detections.extend(file_results)
    all_detections.extend(http_results)
    all_detections.extend(device_results)

    # ==========================================
    # Score
    # ==========================================

    total_score = sum(
        detection["score"]
        for detection in all_detections
    )

    severity = calculate_overall_severity(
        total_score
    )

    # ==========================================
    # Sort Highest Severity First
    # ==========================================

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    all_detections.sort(
        key=lambda x: (
            severity_order.get(
                x["severity"],
                0
            ),
            x["score"]
        ),
        reverse=True
    )

    return {
        "overall_score": total_score,
        "overall_severity": severity,
        "scenario_count": len(all_detections),
        "detections": all_detections
    }