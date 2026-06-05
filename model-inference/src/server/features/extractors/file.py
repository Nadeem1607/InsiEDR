# src/server/features/extractors/file.py

from collections import defaultdict

import pandas as pd
from scipy.stats import entropy


def extract_file_features(file_df):

    print(
        "Extracting file features..."
    )

    df = file_df.copy()

    df["day"] = (
        df["date"]
        .dt.date
    )

    df["hour"] = (
        df["date"]
        .dt.hour
    )

    rows = []

    seen_files = defaultdict(set)

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
                f"File groups: {idx}"
            )

        filenames = set(
            g["filename"]
        )

        new_files = (
            filenames
            -
            seen_files[user]
        )

        filename_counts = (
            g["filename"]
            .value_counts()
        )

        after_hours_count = (

            (
                g["hour"] < 7
            )

            |

            (
                g["hour"] >= 18
            )

        ).sum()

        weekend_count = (

            g["date"]

            .dt.weekday

            >= 5

        ).sum()

        repeat_count = (

            len(g)

            -

            len(filenames)

        )

        rows.append({

            "user":
                user,

            "date":
                day,

            "file_access_count":
                len(g),

            "daily_unique_filename_count":
                len(filenames),

            "daily_new_filename_count":
                len(new_files),

            "daily_file_access_entropy":
                entropy(
                    filename_counts.values
                ),

            "after_hours_file_access":
                after_hours_count,

            "weekend_file_access":
                weekend_count,

            "daily_repeat_file_access_count":
                repeat_count,

            "daily_repeat_file_ratio":
                repeat_count
                /
                max(
                    len(g),
                    1
                ),

            "first_file_access_time":
                g["hour"].min(),

            "last_file_access_time":
                g["hour"].max()

        })

        seen_files[user].update(
            filenames
        )

    print(
        "File feature extraction complete"
    )

    return pd.DataFrame(
        rows
    )