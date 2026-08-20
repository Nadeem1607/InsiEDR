from math import isnan


def safe_get(features, key, default=0):
    value = features.get(key, default)
    if value is None:
        return default
    try:
        if isinstance(value, float) and isnan(value):
            return default
    except Exception:
        pass
    return value


# ==============================================================
# Threshold Revision — v0.5 Hardening  (all thresholds ×5)
#
# Original → New
#   Bulk File Collection        : acc >= 500, unique >= 100
#                               → acc >= 2500, unique >= 500
#   Anomalous File Access       : entropy >= 2.5
#                                 new_files >= 50, repeat <= 0.2
#                               → entropy >= 4.5 (bounded near max)
#                                 new_files >= 250, repeat <= 0.05
#   Credential File Hunting     : new >= 75, unique >= 75, repeat <= 0.15
#                               → new >= 375, unique >= 375, repeat <= 0.04
#   After-Hours File Activity   : after_hours > 0, acc >= 100
#                               → after_hours >= 5, acc >= 500
#   Weekend File Collection     : weekend > 0, acc >= 50
#                               → weekend >= 5, acc >= 250
# ==============================================================

def detect_file_scenarios(features):

    detections = []

    def add_detection(name, severity, score, confidence, reasons):
        detections.append({
            "scenario": name,
            "severity": severity,
            "score": score,
            "confidence": confidence,
            "reasons": reasons
        })

    file_access_count = safe_get(features, "file_access_count")
    unique_files      = safe_get(features, "daily_unique_filename_count")
    new_files         = safe_get(features, "daily_new_filename_count")
    file_entropy      = safe_get(features, "daily_file_access_entropy")
    after_hours       = safe_get(features, "after_hours_file_access")
    weekend_access    = safe_get(features, "weekend_file_access")
    repeat_count      = safe_get(features, "daily_repeat_file_access_count")
    repeat_ratio      = safe_get(features, "daily_repeat_file_ratio")
    first_access      = safe_get(features, "first_file_access_time")
    last_access       = safe_get(features, "last_file_access_time")

    # ----------------------------------------------------------
    # Scenario 1 — Bulk File Collection
    # Original: acc >= 500, unique >= 100
    # v0.5   :  acc >= 2500, unique >= 500
    # ----------------------------------------------------------
    if (file_access_count >= 2500 and unique_files >= 500):
        add_detection(
            name="Bulk File Collection",
            severity="CRITICAL",
            score=25,
            confidence="MEDIUM",
            reasons=[
                f"file_access_count={file_access_count} (threshold >=2500)",
                f"unique_files={unique_files} (threshold >=500)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 2 — Normal Document Editing (benign, unchanged)
    # ----------------------------------------------------------
    if (file_access_count > 0
            and unique_files > 0
            and file_access_count <= 20
            and unique_files <= 20
            and after_hours == 0
            and weekend_access == 0):
        add_detection(
            name="Normal Document Editing",
            severity="LOW",
            score=0,
            confidence="HIGH",
            reasons=["normal file activity", "no after-hours access"]
        )

    # ----------------------------------------------------------
    # Scenario 3 — Anomalous File Access Pattern
    # Original: entropy >= 2.5 OR (new >= 50 AND repeat <= 0.20)
    # v0.5   :  entropy >= 4.5 OR (new >= 250 AND repeat <= 0.05)
    # Note   :  entropy 4.5 is near-maximum for real distributions;
    #           this threshold is only achievable with hundreds of
    #           uniformly distributed unique file paths (scripted).
    # ----------------------------------------------------------
    if (file_entropy >= 4.5
            or (new_files >= 250 and repeat_ratio <= 0.05)):
        add_detection(
            name="Anomalous File Access Pattern",
            severity="HIGH",
            score=15,
            confidence="HIGH",
            reasons=[
                f"file_entropy={file_entropy} (threshold >=4.5)",
                f"new_files={new_files} (threshold >=250)",
                f"repeat_ratio={repeat_ratio} (threshold <=0.05)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 4 — Credential File Hunting
    # Original: new >= 75, unique >= 75, repeat <= 0.15
    # v0.5   :  new >= 375, unique >= 375, repeat <= 0.04
    # ----------------------------------------------------------
    if (new_files >= 375 and repeat_ratio <= 0.04 and unique_files >= 375):
        add_detection(
            name="Credential File Hunting",
            severity="CRITICAL",
            score=20,
            confidence="MEDIUM",
            reasons=[
                f"new_files={new_files} (threshold >=375)",
                f"unique_files={unique_files} (threshold >=375)",
                f"repeat_ratio={repeat_ratio} (threshold <=0.04)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 5 — New Employee Onboarding (benign, bounds raised)
    # Original: acc 20–100, unique 20–100
    # v0.5   :  acc 20–500, unique 20–500
    #           (upper bound raised proportionally so legitimate
    #           onboarding exploration is not crowded out)
    # ----------------------------------------------------------
    if (20 <= file_access_count <= 500
            and 20 <= unique_files <= 500
            and after_hours == 0
            and weekend_access == 0
            and repeat_ratio < 0.5):
        add_detection(
            name="Possible New Employee Onboarding",
            severity="LOW",
            score=0,
            confidence="LOW",
            reasons=[
                f"file_access_count={file_access_count}",
                f"unique_files={unique_files}"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 6 — After-Hours File Activity
    # Original: after_hours > 0, acc >= 100
    # v0.5   :  after_hours >= 5, acc >= 500
    # ----------------------------------------------------------
    if (after_hours >= 5 and file_access_count >= 500):
        add_detection(
            name="After-Hours File Activity",
            severity="HIGH",
            score=10,
            confidence="HIGH",
            reasons=[
                f"after_hours_file_access={after_hours} (threshold >=5)",
                f"file_access_count={file_access_count} (threshold >=500)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 7 — Weekend File Collection Activity
    # Original: weekend > 0, acc >= 50
    # v0.5   :  weekend >= 5, acc >= 250
    # ----------------------------------------------------------
    if (weekend_access >= 5 and file_access_count >= 250):
        add_detection(
            name="Weekend File Collection Activity",
            severity="HIGH",
            score=10,
            confidence="HIGH",
            reasons=[
                f"weekend_file_access={weekend_access} (threshold >=5)",
                f"file_access_count={file_access_count} (threshold >=250)"
            ]
        )

    return detections