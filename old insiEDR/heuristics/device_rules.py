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


def detect_device_scenarios(features):

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

    usb_connect_count = safe_get(
        features,
        "usb_connect_count"
    )

    usb_disconnect_count = safe_get(
        features,
        "usb_disconnect_count"
    )

    after_hours_usb_usage = safe_get(
        features,
        "after_hours_usb_usage"
    )

    daily_device_connect_count = safe_get(
        features,
        "daily_device_connect_count"
    )

    daily_device_usage_flag = safe_get(
        features,
        "daily_device_usage_flag"
    )

    first_usb_usage_time = safe_get(
        features,
        "first_usb_usage_time"
    )

    last_usb_usage_time = safe_get(
        features,
        "last_usb_usage_time"
    )

    # ==========================================
    # Repeated Short USB Connects
    # ==========================================

    if (
        usb_connect_count >= 10
        and usb_disconnect_count >= 10
    ):

        add_detection(
            name="Repeated Short USB Connects",
            severity="HIGH",
            score=15,
            confidence="HIGH",
            reasons=[
                f"usb_connect_count={usb_connect_count}",
                f"usb_disconnect_count={usb_disconnect_count}"
            ]
        )

    return detections