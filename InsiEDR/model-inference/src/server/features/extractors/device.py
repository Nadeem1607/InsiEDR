# src/server/features/extractors/device.py

import pandas as pd


def is_after_hours(timestamp):

    return int(

        timestamp.hour < 7

        or

        timestamp.hour >= 18

    )


def extract_device_features(device_df):

    print(
        "Extracting device features..."
    )

    df = device_df.copy()

    df["day"] = (
        df["date"]
        .dt.date
    )

    rows = []

    for idx, (
        (user, day),
        g
    ) in enumerate(

        df.groupby(
            ["user", "day"]
        )

    ):

        if idx % 50000 == 0:

            print(
                f"Device groups: {idx}"
            )

        connects = g[
            g["activity"]
            == "Connect"
        ]

        disconnects = g[
            g["activity"]
            == "Disconnect"
        ]

        first_connect = 0

        if len(connects) > 0:

            first_connect = (

                connects["date"]

                .dt.hour

                .min()

            )

        last_disconnect = 0

        if len(disconnects) > 0:

            last_disconnect = (

                disconnects["date"]

                .dt.hour

                .max()

            )

        rows.append({

            "user":
                user,

            "date":
                day,

            "usb_connect_count":
                len(connects),

            "usb_disconnect_count":
                len(disconnects),

            "after_hours_usb_usage":
                sum(

                    is_after_hours(x)

                    for x in g["date"]

                ),

            "daily_device_connect_count":
                len(connects),

            "daily_device_usage_flag":
                int(len(g) > 0),

            "first_usb_usage_time":
                first_connect,

            "last_usb_usage_time":
                last_disconnect

        })

    print(
        "Device feature extraction complete"
    )

    return pd.DataFrame(
        rows
    )