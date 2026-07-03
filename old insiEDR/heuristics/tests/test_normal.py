from heuristics.detector import detect_insider_threat


def run_normal_test(
    name,
    features,
    allowed_scenarios=None
):

    if allowed_scenarios is None:
        allowed_scenarios = set()

    result = detect_insider_threat(features)

    detected = {
        d["scenario"]
        for d in result["detections"]
    }

    unexpected = detected - allowed_scenarios

    passed = len(unexpected) == 0

    print("\n" + "=" * 60)
    print(name)
    print("=" * 60)

    print("Detected:")
    print(list(detected))

    print(
        f"Overall Score : {result['overall_score']}"
    )

    print(
        f"Severity      : {result['overall_severity']}"
    )

    print(
        f"Unexpected    : {list(unexpected)}"
    )

    print(
        f"Result        : {'PASS' if passed else 'FAIL'}"
    )

    return passed


def main():

    results = []

    # ==================================================
    # Normal Office Worker
    # ==================================================

    results.append(
        run_normal_test(
            "Normal Office Worker",
            {
                "logon_count": 1,
                "logoff_count": 1,
                "unique_pc_count": 1,
                "after_hours_logon": 0,
                "weekend_logon": 0,

                "file_access_count": 10,
                "daily_unique_filename_count": 8,
                "after_hours_file_access": 0,

                "http_count": 25,
                "unique_url_count": 15,
                "suspicious_url_count": 0,

                "usb_connect_count": 0,
                "usb_disconnect_count": 0
            },
            {
                "Normal Daily Login",
                "Normal Document Editing",
                "Normal Work Browsing"
            }
        )
    )

    # ==================================================
    # Remote Employee
    # ==================================================

    results.append(
        run_normal_test(
            "Remote Employee",
            {
                "logon_count": 1,
                "logoff_count": 1,

                "unique_pc_count": 1,

                "after_hours_logon": 0,

                "file_access_count": 20,

                "daily_unique_filename_count": 15,

                "http_count": 35,

                "unique_url_count": 20,

                "suspicious_url_count": 0
            },
            {
                "Normal Daily Login",
                "Normal Document Editing",
                "Normal Work Browsing"
            }
        )
    )

    # ==================================================
    # New Employee
    # ==================================================

    results.append(
        run_normal_test(
            "New Employee",
            {
                "file_access_count": 50,

                "daily_unique_filename_count": 50,

                "daily_repeat_file_ratio": 0.3,

                "after_hours_file_access": 0,

                "weekend_file_access": 0
            },
            {
                "Possible New Employee Onboarding"
            }
        )
    )

    # ==================================================
    # Online Training
    # ==================================================

    results.append(
        run_normal_test(
            "Online Training",
            {
                "http_count": 40,

                "unique_url_count": 30,

                "job_search_site_visits": 2,

                "suspicious_url_count": 0
            },
            {
                "Online Training Course"
            }
        )
    )

    # ==================================================
    # Light USB Usage
    # ==================================================

    results.append(
        run_normal_test(
            "Occasional USB Usage",
            {
                "usb_connect_count": 1,
                "usb_disconnect_count": 1,
                "daily_device_connect_count": 1
            },
            set()
        )
    )

    # ==================================================
    # Completely Empty Input
    # ==================================================

    results.append(
        run_normal_test(
            "Empty Feature Vector",
            {},
            set()
        )
    )

    # ==================================================
    # Null Input Test
    # ==================================================

    results.append(
        run_normal_test(
            "Null Feature Values",
            {
                "logon_count": None,
                "file_access_count": None,
                "http_count": None,
                "usb_connect_count": None
            },
            set()
        )
    )

    # ==================================================
    # SUMMARY
    # ==================================================

    passed = sum(results)
    total = len(results)

    print("\n")
    print("=" * 60)
    print("NORMAL BEHAVIOR TEST RESULTS")
    print("=" * 60)

    print(f"Passed : {passed}")
    print(f"Failed : {total - passed}")
    print(f"Total  : {total}")

    if passed == total:
        print("\nNO FALSE POSITIVES DETECTED")
    else:
        print("\nPOTENTIAL FALSE POSITIVES FOUND")


if __name__ == "__main__":
    main()