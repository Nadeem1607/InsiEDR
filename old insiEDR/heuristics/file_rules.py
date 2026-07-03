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

def detect_file_scenarios(features):

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

    file_access_count = safe_get(
        features,
        "file_access_count"
    )

    unique_files = safe_get(
        features,
        "daily_unique_filename_count"
    )

    new_files = safe_get(
        features,
        "daily_new_filename_count"
    )

    file_entropy = safe_get(
        features,
        "daily_file_access_entropy"
    )

    after_hours = safe_get(
        features,
        "after_hours_file_access"
    )

    weekend_access = safe_get(
        features,
        "weekend_file_access"
    )

    repeat_count = safe_get(
        features,
        "daily_repeat_file_access_count"
    )

    repeat_ratio = safe_get(
        features,
        "daily_repeat_file_ratio"
    )

    first_access = safe_get(
        features,
        "first_file_access_time"
    )

    last_access = safe_get(
        features,
        "last_file_access_time"
    )

    # ======================================================
    # Scenario 1
    # Bulk Sensitive File Download (Approximation)
    # ======================================================

    if (
        file_access_count >= 500
        and unique_files >= 100
    ):

        add_detection(
            name="Bulk File Collection",
            severity="CRITICAL",
            score=25,
            confidence="MEDIUM",
            reasons=[
                f"file_access_count={file_access_count}",
                f"unique_files={unique_files}"
            ]
        )

    # ======================================================
    # Scenario 2
    # Normal Document Editing
    # ======================================================

    if (
        file_access_count > 0   
        and unique_files > 0
        and file_access_count <= 20
        and unique_files <= 20
        and after_hours == 0
        and weekend_access == 0
    ):  

        add_detection(
            name="Normal Document Editing",
            severity="LOW",
            score=0,
            confidence="HIGH",
            reasons=[
                "normal file activity",
                "no after-hours access"
            ]
        )

    # ======================================================
    # Scenario 3
    # Anomalous File Access Pattern
    # ======================================================

    if (
        file_entropy >= 2.5
        or (
            new_files >= 50
            and repeat_ratio <= 0.2
        )
    ):

        add_detection(
            name="Anomalous File Access Pattern",
            severity="HIGH",
            score=15,
            confidence="HIGH",
            reasons=[
                f"file_entropy={file_entropy}",
                f"new_files={new_files}",
                f"repeat_ratio={repeat_ratio}"
            ]
        )

    # ======================================================
    # Scenario 4
    # Credential File Hunting (Approximation)
    # ======================================================

    if (
        new_files >= 75
        and repeat_ratio <= 0.15
        and unique_files >= 75
    ):

        add_detection(
            name="Credential File Hunting",
            severity="CRITICAL",
            score=20,
            confidence="MEDIUM",
            reasons=[
                f"new_files={new_files}",
                f"unique_files={unique_files}",
                f"repeat_ratio={repeat_ratio}"
            ]
        )

    # ======================================================
    # Scenario 5
    # New Employee Onboarding (Approximation)
    # ======================================================

    if (
        file_access_count >= 20
        and file_access_count <= 100
        and unique_files >= 20
        and unique_files <= 100
        and after_hours == 0
        and weekend_access == 0
        and repeat_ratio < 0.5
    ):

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

    # ======================================================
    # Additional Signal
    # After-Hours File Access
    #
    # Not a standalone PDF scenario
    # but appears repeatedly in multiple
    # insider cases.
    # ======================================================

    if (
        after_hours > 0
        and file_access_count >= 100
    ):

        add_detection(
            name="After-Hours File Activity",
            severity="HIGH",
            score=10,
            confidence="HIGH",
            reasons=[
                f"after_hours_file_access={after_hours}",
                f"file_access_count={file_access_count}"
            ]
        )

    # ======================================================
    # Additional Signal
    # Weekend File Activity
    # ======================================================

    if (
        weekend_access > 0
        and file_access_count >= 50
    ):

        add_detection(
            name="Weekend File Collection Activity",
            severity="HIGH",
            score=10,
            confidence="HIGH",
            reasons=[
                f"weekend_file_access={weekend_access}",
                f"file_access_count={file_access_count}"
            ]
        )

    return detections