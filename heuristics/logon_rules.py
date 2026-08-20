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
#   After-Hours Midnight Access : after_hours > 0   → >= 5
#                                 logon_count >= 3   → >= 15
#                                 first_logon <= 5   → <= 3
#   Multi-PC Lateral Movement   : unique_pc >= 4     → >= 20
#                                 daily_pc >= 4       → >= 20
#                                 pc_entropy >= 1.5   → >= 3.0
#   Short Repeated Sessions     : logon/logoff >= 10 → >= 50
#   Possible Account Sharing    : logon >= 2         → >= 10
#                                 unique_pc >= 2      → >= 10
#                                 ratio > 0.3         → > 0.75
# ==============================================================

def detect_logon_scenarios(features):

    detections = []

    def add_detection(name, severity, score, confidence, reasons):
        detections.append({
            "scenario": name,
            "severity": severity,
            "score": score,
            "confidence": confidence,
            "reasons": reasons
        })

    logon_count          = safe_get(features, "logon_count")
    logoff_count         = safe_get(features, "logoff_count")
    unique_pc_count      = safe_get(features, "unique_pc_count")
    daily_unique_pc_count= safe_get(features, "daily_unique_pc_count")
    after_hours_logon    = safe_get(features, "after_hours_logon")
    after_hours_ratio    = safe_get(features, "daily_after_hours_logon_ratio")
    first_logon_time     = safe_get(features, "first_logon_time")
    last_logoff_time     = safe_get(features, "last_logoff_time")
    weekend_logon        = safe_get(features, "weekend_logon")
    pc_entropy           = safe_get(features, "daily_pc_access_entropy")

    # ----------------------------------------------------------
    # Scenario 1 — After-Hours Midnight Access
    # Original: after_hours > 0 AND (first_logon <= 5 OR logon >= 3)
    # v0.5   :  after_hours >= 5 AND (first_logon <= 3 OR logon >= 15)
    # ----------------------------------------------------------
    midnight_flag = (first_logon_time <= 3 if first_logon_time is not None else False)

    if (after_hours_logon >= 5 and (midnight_flag or logon_count >= 15)):
        add_detection(
            name="After-Hours Midnight Access",
            severity="HIGH",
            score=15,
            confidence="HIGH",
            reasons=[
                f"after_hours_logon={after_hours_logon} (threshold >=5)",
                f"first_logon_time={first_logon_time} (threshold <=3)",
                f"logon_count={logon_count} (threshold >=15)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 2 — Multi-PC Lateral Movement
    # Original: unique_pc >= 4 OR (daily_pc >= 4 AND entropy >= 1.5)
    # v0.5   :  unique_pc >= 20 OR (daily_pc >= 20 AND entropy >= 3.0)
    # ----------------------------------------------------------
    if (unique_pc_count >= 20 or (daily_unique_pc_count >= 20 and pc_entropy >= 3.0)):
        add_detection(
            name="Multi-PC Lateral Movement",
            severity="CRITICAL",
            score=25,
            confidence="VERY_HIGH",
            reasons=[
                f"unique_pc_count={unique_pc_count} (threshold >=20)",
                f"daily_unique_pc_count={daily_unique_pc_count} (threshold >=20)",
                f"pc_entropy={pc_entropy} (threshold >=3.0)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 3 — Normal Daily Login (benign, unchanged)
    # ----------------------------------------------------------
    if (logon_count == 1 and unique_pc_count <= 1
            and after_hours_logon == 0 and weekend_logon == 0):
        add_detection(
            name="Normal Daily Login",
            severity="LOW",
            score=0,
            confidence="VERY_HIGH",
            reasons=["single logon", "no after-hours access", "no weekend access"]
        )

    # ----------------------------------------------------------
    # Scenario 4 — Short Repeated Sessions
    # Original: logon/logoff >= 10, mismatch <= 2
    # v0.5   :  logon/logoff >= 50, mismatch <= 5
    # ----------------------------------------------------------
    mismatch = abs(logon_count - logoff_count)

    if (logon_count >= 50 and logoff_count >= 50 and mismatch <= 5):
        add_detection(
            name="Short Repeated Sessions",
            severity="HIGH",
            score=15,
            confidence="MEDIUM",
            reasons=[
                f"logon_count={logon_count} (threshold >=50)",
                f"logoff_count={logoff_count} (threshold >=50)",
                f"mismatch={mismatch} (threshold <=5)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 5 — Possible Account Sharing
    # Original: logon >= 2, unique_pc >= 2, ratio > 0.30
    # v0.5   :  logon >= 10, unique_pc >= 10, ratio > 0.75
    # ----------------------------------------------------------
    if (logon_count >= 10 and unique_pc_count >= 10 and after_hours_ratio > 0.75):
        add_detection(
            name="Possible Account Sharing",
            severity="HIGH",
            score=10,
            confidence="LOW",
            reasons=[
                f"logon_count={logon_count} (threshold >=10)",
                f"unique_pc_count={unique_pc_count} (threshold >=10)",
                f"after_hours_ratio={after_hours_ratio} (threshold >0.75)"
            ]
        )

    return detections