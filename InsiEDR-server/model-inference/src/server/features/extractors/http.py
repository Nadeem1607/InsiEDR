# src/server/features/extractors/http.py

import os
from collections import defaultdict
from urllib.parse import urlparse

import pandas as pd
from scipy.stats import entropy


JOB_SEARCH_DOMAINS = {
    "monster.com",
    "indeed.com",
    "careerbuilder.com",
    "dice.com"
}

FILE_SHARING_DOMAINS = {
    "dropbox.com",
    "box.com",
    "mediafire.com",
    "rapidshare.com"
}

SUSPICIOUS_DOMAINS = {
    "wikileaks.org",
    "dropbox.com",
    "mediafire.com",
    "rapidshare.com"
}


def extract_domain(url):

    try:

        domain = (
            urlparse(
                str(url)
            )
            .netloc
            .lower()
        )

        if domain.startswith(
            "www."
        ):

            domain = domain[4:]

        return domain

    except Exception:

        return ""


def extract_http_features(
    cert_root
):

    print(
        "Extracting HTTP features..."
    )

    http_path = os.path.join(
        cert_root,
        "http.csv"
    )

    user_day_data = {}

    CHUNK_SIZE = 50000

    chunk_id = 0

    for chunk in pd.read_csv(

        http_path,

        usecols=[
            "date",
            "user",
            "url"
        ],

        chunksize=CHUNK_SIZE

    ):

        chunk_id += 1

        print(
            f"HTTP chunk {chunk_id}"
        )

        chunk["date"] = pd.to_datetime(
            chunk["date"]
        )

        chunk["day"] = (
            chunk["date"]
            .dt.date
        )

        chunk["hour"] = (
            chunk["date"]
            .dt.hour
        )

        for row in chunk.itertuples():

            key = (
                row.user,
                row.day
            )

            domain = extract_domain(
                row.url
            )

            if key not in user_day_data:

                user_day_data[key] = {

                    "http_count": 0,

                    "urls": set(),

                    "domains": [],

                    "after_hours": 0,

                    "job_search": 0,

                    "file_sharing": 0,

                    "suspicious": 0
                }

            d = user_day_data[key]

            d["http_count"] += 1

            d["urls"].add(
                row.url
            )

            d["domains"].append(
                domain
            )

            if (
                row.hour < 7
                or row.hour >= 18
            ):

                d["after_hours"] += 1

            if domain in JOB_SEARCH_DOMAINS:

                d["job_search"] += 1

            if domain in FILE_SHARING_DOMAINS:

                d["file_sharing"] += 1

            if domain in SUSPICIOUS_DOMAINS:

                d["suspicious"] += 1

    print(
        "Building HTTP feature table..."
    )

    rows = []

    seen_domains = defaultdict(set)

    total_groups = len(
        user_day_data
    )

    for idx, (
        (user, day),
        d
    ) in enumerate(
        user_day_data.items()
    ):

        if idx % 10000 == 0:

            print(
                f"HTTP groups processed: "
                f"{idx}/{total_groups}"
            )

        unique_domains = set(
            d["domains"]
        )

        domain_counts = pd.Series(
            d["domains"]
        ).value_counts()

        entropy_value = 0.0

        if len(domain_counts) > 0:

            entropy_value = entropy(
                domain_counts.values
            )

        new_domains = (

            unique_domains

            -

            seen_domains[user]

        )

        seen_domains[user].update(
            unique_domains
        )

        external_domains = [

            x

            for x in unique_domains

            if x != ""

        ]

        external_ratio = (

            len(external_domains)

            /

            max(
                len(unique_domains),
                1
            )

        )

        rows.append({

            "user":
                user,

            "date":
                day,

            "http_count":
                d["http_count"],

            "daily_http_request_count":
                d["http_count"],

            "unique_url_count":
                len(
                    d["urls"]
                ),

            "suspicious_url_count":
                d["suspicious"],

            "file_sharing_site_visits":
                d["file_sharing"],

            "job_search_site_visits":
                d["job_search"],

            "http_after_hours":
                d["after_hours"],

            "daily_unique_domain_count":
                len(
                    unique_domains
                ),

            "daily_new_domain_count":
                len(
                    new_domains
                ),

            "daily_domain_access_entropy":
                entropy_value,

            "daily_external_domain_ratio":
                external_ratio

        })

    result = pd.DataFrame(
        rows
    )

    result = result.fillna(0)

    print(
        "HTTP feature extraction complete"
    )

    return result