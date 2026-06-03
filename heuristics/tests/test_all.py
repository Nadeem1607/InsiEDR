from heuristics.detector import detect_insider_threat


def run_test(
    name,
    features,
    expected_scenario
):

    result = detect_insider_threat(features)

    detected = {
        d["scenario"]
        for d in result["detections"]
    }

    passed = expected_scenario in detected

    print("\n" + "=" * 60)
    print(name)
    print("=" * 60)

    print(
        f"Expected : {expected_scenario}"
    )

    print(
        f"Detected : {list(detected)}"
    )

    print(
        f"Result   : {'PASS' if passed else 'FAIL'}"
    )

    return passed


def main():

    results = []

    # ==================================================
    # LOGON TESTS
    # ==================================================

    results.append(
        run_test(
            "After Hours Midnight Access",
            {
                "after_hours_logon": 1,
                "first_logon_time": 2,
                "logon_count": 5
            },
            "After-Hours Midnight Access"
        )
    )

    results.append(
        run_test(
            "Multi-PC Lateral Movement",
            {
                "unique_pc_count": 6,
                "daily_unique_pc_count": 6,
                "daily_pc_access_entropy": 2.5
            },
            "Multi-PC Lateral Movement"
        )
    )

    results.append(
        run_test(
            "Normal Daily Login",
            {
                "logon_count": 1,
                "after_hours_logon": 0,
                "weekend_logon": 0,
                "unique_pc_count": 1
            },
            "Normal Daily Login"
        )
    )

    results.append(
        run_test(
            "Short Repeated Sessions",
            {
                "logon_count": 15,
                "logoff_count": 15
            },
            "Short Repeated Sessions"
        )
    )

    results.append(
        run_test(
            "Possible Account Sharing",
            {
                "logon_count": 3,
                "unique_pc_count": 3,
                "daily_after_hours_logon_ratio": 0.5
            },
            "Possible Account Sharing"
        )
    )

    # ==================================================
    # FILE TESTS
    # ==================================================

    results.append(
        run_test(
            "Bulk File Collection",
            {
                "file_access_count": 800,
                "daily_unique_filename_count": 300
            },
            "Bulk File Collection"
        )
    )

    results.append(
        run_test(
            "Normal Document Editing",
            {
                "file_access_count": 10,
                "daily_unique_filename_count": 10,
                "after_hours_file_access": 0,
                "weekend_file_access": 0
            },
            "Normal Document Editing"
        )
    )

    results.append(
        run_test(
            "Anomalous File Access Pattern",
            {
                "daily_file_access_entropy": 3.0,
                "daily_new_filename_count": 75,
                "daily_repeat_file_ratio": 0.1
            },
            "Anomalous File Access Pattern"
        )
    )

    results.append(
        run_test(
            "Credential File Hunting",
            {
                "daily_new_filename_count": 100,
                "daily_unique_filename_count": 100,
                "daily_repeat_file_ratio": 0.1
            },
            "Credential File Hunting"
        )
    )

    results.append(
        run_test(
            "Possible New Employee Onboarding",
            {
                "file_access_count": 50,
                "daily_unique_filename_count": 50,
                "after_hours_file_access": 0,
                "weekend_file_access": 0,
                "daily_repeat_file_ratio": 0.3
            },
            "Possible New Employee Onboarding"
        )
    )

    # ==================================================
    # HTTP TESTS
    # ==================================================

    results.append(
        run_test(
            "Cloud Storage Exfiltration",
            {
                "file_sharing_site_visits": 8,
                "http_after_hours": 1
            },
            "Cloud Storage Exfiltration"
        )
    )

    results.append(
        run_test(
            "Research on Dark Web Tools",
            {
                "suspicious_url_count": 5,
                "unique_url_count": 5
            },
            "Research on Dark Web Tools"
        )
    )

    results.append(
        run_test(
            "Personal Email File Forwarding",
            {
                "file_sharing_site_visits": 10,
                "http_after_hours": 1,
                "daily_external_domain_ratio": 0.8
            },
            "Personal Email File Forwarding"
        )
    )

    results.append(
        run_test(
            "Malware C2 Communication",
            {
                "http_count": 150,
                "unique_url_count": 1,
                "suspicious_url_count": 1
            },
            "Malware C2 Communication"
        )
    )

    results.append(
        run_test(
            "Online Training Course",
            {
                "suspicious_url_count": 0,
                "unique_url_count": 30,
                "job_search_site_visits": 2
            },
            "Online Training Course"
        )
    )

    results.append(
        run_test(
            "Excessive Personal Browsing",
            {
                "http_count": 100,
                "suspicious_url_count": 0,
                "file_sharing_site_visits": 0
            },
            "Excessive Personal Browsing"
        )
    )

    results.append(
        run_test(
            "Tor Network Access Attempt",
            {
                "suspicious_url_count": 2,
                "http_after_hours": 1
            },
            "Tor Network Access Attempt"
        )
    )

    results.append(
        run_test(
            "Social Media During Work Hours",
            {
                "http_count": 60,
                "suspicious_url_count": 0,
                "file_sharing_site_visits": 0,
                "job_search_site_visits": 0
            },
            "Social Media During Work Hours"
        )
    )

    results.append(
        run_test(
            "Phishing Site Visit",
            {
                "suspicious_url_count": 1,
                "unique_url_count": 1,
                "http_count": 1
            },
            "Phishing Site Visit"
        )
    )

    # ==================================================
    # DEVICE TESTS
    # ==================================================

    results.append(
        run_test(
            "Repeated Short USB Connects",
            {
                "usb_connect_count": 12,
                "usb_disconnect_count": 12
            },
            "Repeated Short USB Connects"
        )
    )

    # ==================================================
    # SUMMARY
    # ==================================================

    passed = sum(results)
    total = len(results)

    print("\n")
    print("=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print(f"Passed : {passed}")
    print(f"Failed : {total - passed}")
    print(f"Total  : {total}")

    if passed == total:
        print("\nALL TESTS PASSED")
    else:
        print("\nSOME TESTS FAILED")


if __name__ == "__main__":
    main()