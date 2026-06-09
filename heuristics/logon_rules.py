from math import isnan


# ==========================================================
# Utilities
# ==========================================================

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


# ==========================================================
# Main Detector
# ==========================================================

def detect_logon_scenarios(features):

    detections = []

    def add_detection(
        name,
        severity,
        score,
        confidence,
        reasons
    ):

        detections.append(
            {
                "scenario": name,
                "severity": severity,
                "score": score,
                "confidence": confidence,
                "reasons": reasons
            }
        )

    # ======================================================
    # Feature Extraction
    # ======================================================

    logon_count = safe_get(features, "logon_count")
    logoff_count = safe_get(features, "logoff_count")

    unique_pc_count = safe_get(
        features,
        "unique_pc_count"
    )

    daily_unique_pc_count = safe_get(
        features,
        "daily_unique_pc_count"
    )

    after_hours_logon = safe_get(
        features,
        "after_hours_logon"
    )

    after_hours_ratio = safe_get(
        features,
        "daily_after_hours_logon_ratio"
    )

    first_logon_time = safe_get(
        features,
        "first_logon_time"
    )

    last_logoff_time = safe_get(
        features,
        "last_logoff_time"
    )

    weekend_logon = safe_get(
        features,
        "weekend_logon"
    )

    pc_entropy = safe_get(
        features,
        "daily_pc_access_entropy"
    )

    # ======================================================
    # Scenario 1
    # After-Hours Midnight Access
    # ======================================================

    midnight_flag = (
        first_logon_time <= 5
        if first_logon_time is not None
        else False
    )

    if (
        after_hours_logon > 0
        and (
            midnight_flag
            or logon_count >= 3
        )
    ):

        add_detection(
            name="After-Hours Midnight Access",
            severity="HIGH",
            score=15,
            confidence="HIGH",
            reasons=[
                f"after_hours_logon={after_hours_logon}",
                f"first_logon_time={first_logon_time}",
                f"logon_count={logon_count}"
            ]
        )

    # ======================================================
    # Scenario 2
    # Multi-PC Lateral Movement
    # ======================================================

    if (
        unique_pc_count >= 4
        or (
            daily_unique_pc_count >= 4
            and pc_entropy >= 1.5
        )
    ):

        add_detection(
            name="Multi-PC Lateral Movement",
            severity="CRITICAL",
            score=25,
            confidence="VERY_HIGH",
            reasons=[
                f"unique_pc_count={unique_pc_count}",
                f"daily_unique_pc_count={daily_unique_pc_count}",
                f"pc_entropy={pc_entropy}"
            ]
        )

    # ======================================================
    # Scenario 3
    # Normal Daily Login
    # ======================================================

    if (
        logon_count == 1
        and unique_pc_count <= 1
        and after_hours_logon == 0
        and weekend_logon == 0
    ):

        add_detection(
            name="Normal Daily Login",
            severity="LOW",
            score=0,
            confidence="VERY_HIGH",
            reasons=[
                "single logon",
                "no after-hours access",
                "no weekend access"
            ]
        )

    # ======================================================
    # Scenario 4
    # Short Repeated Sessions
    # ======================================================

    mismatch = abs(
        logon_count - logoff_count
    )

    if (
        logon_count >= 10
        and logoff_count >= 10
        and mismatch <= 2
    ):

        add_detection(
            name="Short Repeated Sessions",
            severity="HIGH",
            score=15,
            confidence="MEDIUM",
            reasons=[
                f"logon_count={logon_count}",
                f"logoff_count={logoff_count}"
            ]
        )

    # ======================================================
    # Scenario 5
    # Account Sharing Detected (Approximation)
    # ======================================================

    if (
        logon_count >= 2
        and unique_pc_count >= 2
        and after_hours_ratio > 0.3
    ):

        add_detection(
            name="Possible Account Sharing",
            severity="HIGH",
            score=10,
            confidence="LOW",
            reasons=[
                f"logon_count={logon_count}",
                f"unique_pc_count={unique_pc_count}",
                f"after_hours_ratio={after_hours_ratio}"
            ]
        )

    return detections