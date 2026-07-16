from heuristics.detector import detect_insider_threat


def run_mixed_test(
    name,
    features,
    expected_scenarios
):

    result = detect_insider_threat(features)

    detected = {
        d["scenario"]
        for d in result["detections"]
    }

    missing = [
        s for s in expected_scenarios
        if s not in detected
    ]

    passed = len(missing) == 0

    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    print(
        f"Overall Score    : {result['overall_score']}"
    )

    print(
        f"Overall Severity : {result['overall_severity']}"
    )

    print("\nDetected Scenarios:")

    for scenario in sorted(detected):
        print(f"  - {scenario}")

    print("\nExpected Scenarios:")

    for scenario in expected_scenarios:
        print(f"  - {scenario}")

    print("\nMissing:")

    if missing:
        for m in missing:
            print(f"  - {m}")
    else:
        print("  None")

    print(
        f"\nResult : {'PASS' if passed else 'FAIL'}"
    )

    return passed


def main():

    results = []

    # ==================================================
    # Scenario 1
    # Insider Data Theft
    # ==================================================

    results.append(
        run_mixed_test(
            "INSIDER DATA THEFT",
            {
                "after_hours_logon": 1,
                "first_logon_time": 2,
                "logon_count": 6,

                "unique_pc_count": 5,
                "daily_unique_pc_count": 5,
                "daily_pc_access_entropy": 2.5,

                "file_access_count": 800,
                "daily_unique_filename_count": 300,

                "file_sharing_site_visits": 10,
                "http_after_hours": 1
            },
            [
                "After-Hours Midnight Access",
                "Multi-PC Lateral Movement",
                "Bulk File Collection",
                "Cloud Storage Exfiltration"
            ]
        )
    )

    # ==================================================
    # Scenario 2
    # Credential Hunting
    # ==================================================

    results.append(
        run_mixed_test(
            "CREDENTIAL HUNTING",
            {
                "daily_new_filename_count": 150,
                "daily_unique_filename_count": 150,
                "daily_repeat_file_ratio": 0.05,

                "suspicious_url_count": 5,
                "unique_url_count": 5
            },
            [
                "Credential File Hunting",
                "Research on Dark Web Tools"
            ]
        )
    )

    # ==================================================
    # Scenario 3
    # Malware Infection
    # ==================================================

    results.append(
        run_mixed_test(
            "MALWARE INFECTION",
            {
                "http_count": 150,
                "unique_url_count": 1,
                "suspicious_url_count": 1,

                "after_hours_logon": 1,
                "first_logon_time": 3,
                "logon_count": 4
            },
            [
                "Malware C2 Communication",
                "After-Hours Midnight Access"
            ]
        )
    )

    # ==================================================
    # Scenario 4
    # Tor + Exfiltration
    # ==================================================

    results.append(
        run_mixed_test(
            "TOR + EXFILTRATION",
            {
                "suspicious_url_count": 3,
                "http_after_hours": 1,
                "unique_url_count": 4,

                "file_sharing_site_visits": 8,
                "daily_external_domain_ratio": 0.8
            },
            [
                "Tor Network Access Attempt",
                "Research on Dark Web Tools",
                "Personal Email File Forwarding"
            ]
        )
    )

    # ==================================================
    # Scenario 5
    # Aggressive USB Activity
    # ==================================================

    results.append(
        run_mixed_test(
            "USB ACTIVITY",
            {
                "usb_connect_count": 12,
                "usb_disconnect_count": 12,

                "after_hours_logon": 1,
                "first_logon_time": 1,
                "logon_count": 5
            },
            [
                "Repeated Short USB Connects",
                "After-Hours Midnight Access"
            ]
        )
    )

    # ==================================================
    # Scenario 6
    # Benign Employee
    # ==================================================

    results.append(
        run_mixed_test(
            "BENIGN EMPLOYEE",
            {
                "logon_count": 1,
                "logoff_count": 1,
                "unique_pc_count": 1,

                "file_access_count": 10,
                "daily_unique_filename_count": 10,

                "http_count": 20,
                "unique_url_count": 15,
                "suspicious_url_count": 0
            },
            [
                "Normal Daily Login",
                "Normal Document Editing",
                "Normal Work Browsing"
            ]
        )
    )

    # ==================================================
    # Summary
    # ==================================================

    passed = sum(results)
    total = len(results)

    print("\n")
    print("=" * 70)
    print("MIXED SCENARIO TEST RESULTS")
    print("=" * 70)

    print(f"Passed : {passed}")
    print(f"Failed : {total - passed}")
    print(f"Total  : {total}")

    if passed == total:
        print("\nALL MIXED TESTS PASSED")
    else:
        print("\nINVESTIGATE FAILED MIXED TESTS")


if __name__ == "__main__":
    main()