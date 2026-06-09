import pandas as pd


INSIDERS_FILE = r"data/CERT/r4.2/answers/answers/insiders.csv"


def load_true_insiders():

    insiders = pd.read_csv(
        INSIDERS_FILE
    )

    r42 = insiders[
        insiders["dataset"] == 4.2
    ]

    return set(
        r42["user"]
        .astype(str)
        .unique()
    )


def evaluate_method(
        users,
        insiders,
        score_column
):

    ranked = users.sort_values(

        score_column,

        ascending=False

    )

    print()
    print("=" * 80)
    print(score_column.upper())
    print("=" * 80)
    print()

    print(

        ranked[
            [
                "user",
                score_column
            ]
        ].head(20)

    )

    print()

    for k in [

        5,
        10,
        25,
        50,
        100

    ]:

        top_users = set(

            ranked

            .head(k)["user"]

            .astype(str)

        )

        overlap = sorted(

            insiders.intersection(
                top_users
            )

        )

        print(
            f"Top-{k}"
        )

        print(
            "Detected:",
            len(overlap)
        )

        print(
            "Recall:",
            len(overlap)
            / len(insiders)
        )

        print(
            overlap
        )

        print()


def main():

    insiders = (
        load_true_insiders()
    )

    users = pd.read_csv(
        "top_users.csv"
    )

    candidate_scores = [

        c

        for c in users.columns

        if c.startswith(
            "score"
        )

    ]

    print()
    print("=" * 80)
    print(
        "AVAILABLE METHODS"
    )
    print("=" * 80)

    print(
        candidate_scores
    )

    for score_column in candidate_scores:

        evaluate_method(

            users,
            insiders,
            score_column

        )


if __name__ == "__main__":
    main()