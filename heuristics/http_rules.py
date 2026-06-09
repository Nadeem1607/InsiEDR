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

def detect_http_scenarios(features):

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

    http_count = safe_get(
        features,
        "http_count"
    )

    daily_http_request_count = safe_get(
        features,
        "daily_http_request_count"
    )

    unique_url_count = safe_get(
        features,
        "unique_url_count"
    )

    suspicious_url_count = safe_get(
        features,
        "suspicious_url_count"
    )

    file_sharing_visits = safe_get(
        features,
        "file_sharing_site_visits"
    )

    job_search_visits = safe_get(
        features,
        "job_search_site_visits"
    )

    http_after_hours = safe_get(
        features,
        "http_after_hours"
    )

    unique_domains = safe_get(
        features,
        "daily_unique_domain_count"
    )

    new_domains = safe_get(
        features,
        "daily_new_domain_count"
    )

    domain_entropy = safe_get(
        features,
        "daily_domain_access_entropy"
    )

    external_ratio = safe_get(
        features,
        "daily_external_domain_ratio"
    )

    # ======================================================
    # Scenario 1
    # Normal Work Browsing
    # ======================================================

    if (
        http_count > 0
        and suspicious_url_count == 0
        and file_sharing_visits == 0
        and job_search_visits == 0
        and http_after_hours == 0
        and 10 <= unique_url_count <= 50
    ):

        add_detection(
            name="Normal Work Browsing",
            severity="LOW",
            score=0,
            confidence="HIGH",
            reasons=[
                "normal browsing behaviour"
            ]
        )

    # ======================================================
    # Scenario 2
    # Cloud Storage Exfiltration
    # Approximation
    # ======================================================

    if (
        file_sharing_visits >= 5
        and http_after_hours > 0
    ):

        add_detection(
            name="Cloud Storage Exfiltration",
            severity="CRITICAL",
            score=25,
            confidence="MEDIUM",
            reasons=[
                f"file_sharing_site_visits={file_sharing_visits}",
                f"http_after_hours={http_after_hours}"
            ]
        )

    # ======================================================
    # Scenario 3
    # Research on Dark Web Tools
    # ======================================================

    if (
        suspicious_url_count >= 3
        and unique_url_count <= 10
    ):

        add_detection(
            name="Research on Dark Web Tools",
            severity="HIGH",
            score=15,
            confidence="HIGH",
            reasons=[
                f"suspicious_url_count={suspicious_url_count}"
            ]
        )

    # ======================================================
    # Scenario 4
    # Personal Email File Forwarding
    # Approximation
    # ======================================================

    if (
        file_sharing_visits >= 8
        and http_after_hours > 0
        and external_ratio >= 0.5
    ):

        add_detection(
            name="Personal Email File Forwarding",
            severity="CRITICAL",
            score=20,
            confidence="MEDIUM",
            reasons=[
                f"file_sharing_site_visits={file_sharing_visits}",
                f"external_domain_ratio={external_ratio}"
            ]
        )

    # ======================================================
    # Scenario 5
    # Malware C2 Communication
    # Approximation
    # ======================================================

    if (
        http_count >= 100
        and unique_url_count <= 2
        and suspicious_url_count >= 1
    ):

        add_detection(
            name="Malware C2 Communication",
            severity="CRITICAL",
            score=25,
            confidence="MEDIUM",
            reasons=[
                f"http_count={http_count}",
                f"unique_url_count={unique_url_count}",
                f"suspicious_url_count={suspicious_url_count}"
            ]
        )

    # ======================================================
    # Scenario 6
    # Online Training Course
    # Approximation
    # ======================================================

    if (
        suspicious_url_count == 0
        and 20 <= unique_url_count <= 50
        and 1 <= job_search_visits <= 3
    ):

        add_detection(
            name="Online Training Course",
            severity="LOW",
            score=0,
            confidence="LOW",
            reasons=[
                f"job_search_site_visits={job_search_visits}"
            ]
        )

    # ======================================================
    # Scenario 7
    # Excessive Personal Shopping
    # Approximation
    # ======================================================

    if (
        http_count >= 80
        and suspicious_url_count == 0
        and file_sharing_visits == 0
    ):

        add_detection(
            name="Excessive Personal Browsing",
            severity="LOW",
            score=0,
            confidence="LOW",
            reasons=[
                f"http_count={http_count}"
            ]
        )

    # ======================================================
    # Scenario 8
    # Tor Network Access Attempt
    # ======================================================

    if (
        suspicious_url_count >= 2
        and http_after_hours > 0
    ):

        add_detection(
            name="Tor Network Access Attempt",
            severity="HIGH",
            score=15,
            confidence="HIGH",
            reasons=[
                f"suspicious_url_count={suspicious_url_count}",
                f"http_after_hours={http_after_hours}"
            ]
        )

    # ======================================================
    # Scenario 9
    # Social Media During Work Hours
    # Approximation
    # ======================================================

    if (
        50 <= http_count <= 100
        and suspicious_url_count == 0
        and file_sharing_visits == 0
        and job_search_visits == 0
    ):

        add_detection(
            name="Social Media During Work Hours",
            severity="LOW",
            score=0,
            confidence="LOW",
            reasons=[
                f"http_count={http_count}"
            ]
        )

    # ======================================================
    # Scenario 10
    # Phishing Site Visit
    # Approximation
    # ======================================================

    if (
        suspicious_url_count == 1
        and unique_url_count <= 2
        and http_count <= 5
    ):

        add_detection(
            name="Phishing Site Visit",
            severity="CRITICAL",
            score=20,
            confidence="MEDIUM",
            reasons=[
                f"suspicious_url_count={suspicious_url_count}",
                f"unique_url_count={unique_url_count}"
            ]
        )

    return detections