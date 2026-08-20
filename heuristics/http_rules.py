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
#   Cloud Storage Exfiltration    : sharing >= 5, after > 0
#                                 → sharing >= 25, after >= 5
#   Research on Dark Web Tools    : suspicious >= 3, unique <= 10
#                                 → suspicious >= 15, unique <= 5
#   Personal Email File Forwarding: sharing >= 8, after > 0, ext >= 0.5
#                                 → sharing >= 40, after >= 5, ext >= 0.85
#   Malware C2 Communication      : http >= 100, unique <= 2, susp >= 1
#                                 → http >= 500, unique <= 2, susp >= 3
#   Tor Network Access            : suspicious >= 2, after > 0
#                                 → suspicious >= 10, after >= 3
#   Phishing Site Visit           : suspicious == 1, unique <= 2, http <= 5
#                                 → suspicious >= 5, unique <= 5, http <= 25
# ==============================================================

def detect_http_scenarios(features):

    detections = []

    def add_detection(name, severity, score, confidence, reasons):
        detections.append({
            "scenario": name,
            "severity": severity,
            "score": score,
            "confidence": confidence,
            "reasons": reasons
        })

    http_count              = safe_get(features, "http_count")
    daily_http_request_count= safe_get(features, "daily_http_request_count")
    unique_url_count        = safe_get(features, "unique_url_count")
    suspicious_url_count    = safe_get(features, "suspicious_url_count")
    file_sharing_visits     = safe_get(features, "file_sharing_site_visits")
    job_search_visits       = safe_get(features, "job_search_site_visits")
    http_after_hours        = safe_get(features, "http_after_hours")
    unique_domains          = safe_get(features, "daily_unique_domain_count")
    new_domains             = safe_get(features, "daily_new_domain_count")
    domain_entropy          = safe_get(features, "daily_domain_access_entropy")
    external_ratio          = safe_get(features, "daily_external_domain_ratio")

    # ----------------------------------------------------------
    # Scenario 1 — Normal Work Browsing (benign, unchanged)
    # ----------------------------------------------------------
    if (http_count > 0
            and suspicious_url_count == 0
            and file_sharing_visits == 0
            and job_search_visits == 0
            and http_after_hours == 0
            and 10 <= unique_url_count <= 50):
        add_detection(
            name="Normal Work Browsing",
            severity="LOW",
            score=0,
            confidence="HIGH",
            reasons=["normal browsing behaviour"]
        )

    # ----------------------------------------------------------
    # Scenario 2 — Cloud Storage Exfiltration
    # Original: sharing >= 5, after > 0
    # v0.5   :  sharing >= 25, after >= 5
    # ----------------------------------------------------------
    if (file_sharing_visits >= 25 and http_after_hours >= 5):
        add_detection(
            name="Cloud Storage Exfiltration",
            severity="CRITICAL",
            score=25,
            confidence="MEDIUM",
            reasons=[
                f"file_sharing_site_visits={file_sharing_visits} (threshold >=25)",
                f"http_after_hours={http_after_hours} (threshold >=5)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 3 — Research on Dark Web Tools
    # Original: suspicious >= 3, unique <= 10
    # v0.5   :  suspicious >= 15, unique <= 5
    # ----------------------------------------------------------
    if (suspicious_url_count >= 15 and unique_url_count <= 5):
        add_detection(
            name="Research on Dark Web Tools",
            severity="HIGH",
            score=15,
            confidence="HIGH",
            reasons=[
                f"suspicious_url_count={suspicious_url_count} (threshold >=15)",
                f"unique_url_count={unique_url_count} (threshold <=5)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 4 — Personal Email File Forwarding
    # Original: sharing >= 8, after > 0, ext >= 0.50
    # v0.5   :  sharing >= 40, after >= 5, ext >= 0.85
    # ----------------------------------------------------------
    if (file_sharing_visits >= 40
            and http_after_hours >= 5
            and external_ratio >= 0.85):
        add_detection(
            name="Personal Email File Forwarding",
            severity="CRITICAL",
            score=20,
            confidence="MEDIUM",
            reasons=[
                f"file_sharing_site_visits={file_sharing_visits} (threshold >=40)",
                f"http_after_hours={http_after_hours} (threshold >=5)",
                f"external_domain_ratio={external_ratio} (threshold >=0.85)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 5 — Malware C2 Communication
    # Original: http >= 100, unique <= 2, suspicious >= 1
    # v0.5   :  http >= 500, unique <= 2, suspicious >= 3
    # Note   :  unique_url_count kept at <=2 (already very tight);
    #           suspicious raised 1→3 and http raised 100→500.
    # ----------------------------------------------------------
    if (http_count >= 500
            and unique_url_count <= 2
            and suspicious_url_count >= 3):
        add_detection(
            name="Malware C2 Communication",
            severity="CRITICAL",
            score=25,
            confidence="MEDIUM",
            reasons=[
                f"http_count={http_count} (threshold >=500)",
                f"unique_url_count={unique_url_count} (threshold <=2)",
                f"suspicious_url_count={suspicious_url_count} (threshold >=3)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 6 — Online Training Course (benign, unchanged)
    # ----------------------------------------------------------
    if (suspicious_url_count == 0
            and 20 <= unique_url_count <= 50
            and 1 <= job_search_visits <= 3):
        add_detection(
            name="Online Training Course",
            severity="LOW",
            score=0,
            confidence="LOW",
            reasons=[f"job_search_site_visits={job_search_visits}"]
        )

    # ----------------------------------------------------------
    # Scenario 7 — Excessive Personal Browsing (benign, unchanged)
    # ----------------------------------------------------------
    if (http_count >= 80
            and suspicious_url_count == 0
            and file_sharing_visits == 0):
        add_detection(
            name="Excessive Personal Browsing",
            severity="LOW",
            score=0,
            confidence="LOW",
            reasons=[f"http_count={http_count}"]
        )

    # ----------------------------------------------------------
    # Scenario 8 — Tor Network Access Attempt
    # Original: suspicious >= 2, after > 0
    # v0.5   :  suspicious >= 10, after >= 3
    # ----------------------------------------------------------
    if (suspicious_url_count >= 10 and http_after_hours >= 3):
        add_detection(
            name="Tor Network Access Attempt",
            severity="HIGH",
            score=15,
            confidence="HIGH",
            reasons=[
                f"suspicious_url_count={suspicious_url_count} (threshold >=10)",
                f"http_after_hours={http_after_hours} (threshold >=3)"
            ]
        )

    # ----------------------------------------------------------
    # Scenario 9 — Social Media During Work Hours (benign, unchanged)
    # ----------------------------------------------------------
    if (50 <= http_count <= 100
            and suspicious_url_count == 0
            and file_sharing_visits == 0
            and job_search_visits == 0):
        add_detection(
            name="Social Media During Work Hours",
            severity="LOW",
            score=0,
            confidence="LOW",
            reasons=[f"http_count={http_count}"]
        )

    # ----------------------------------------------------------
    # Scenario 10 — Phishing Site Visit
    # Original: suspicious == 1, unique <= 2, http <= 5
    # v0.5   :  suspicious >= 5, unique <= 5, http <= 25
    # ----------------------------------------------------------
    if (suspicious_url_count >= 5
            and unique_url_count <= 5
            and http_count <= 25):
        add_detection(
            name="Phishing Site Visit",
            severity="CRITICAL",
            score=20,
            confidence="MEDIUM",
            reasons=[
                f"suspicious_url_count={suspicious_url_count} (threshold >=5)",
                f"unique_url_count={unique_url_count} (threshold <=5)",
                f"http_count={http_count} (threshold <=25)"
            ]
        )

    return detections