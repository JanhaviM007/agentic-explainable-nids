import pandas as pd
import numpy as np


def clean_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean a CICIDS2017 dataframe.

    Steps:
    1. Strip whitespace from column names.
    2. Strip whitespace from labels.
    3. Replace infinite values with NaN.
    4. Remove rows containing missing values.
    5. Remove duplicate rows.
    """

    df = df.copy()

    # 1. Clean column names
    df.columns = df.columns.str.strip()

    # 2. Clean target labels
    if "Label" in df.columns:
        df["Label"] = df["Label"].astype(str).str.strip()

    # 3. Replace infinite values with NaN
    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    # 4. Remove rows containing missing values
    df.dropna(inplace=True)

    # 5. Remove duplicate rows
    df.drop_duplicates(inplace=True)

    # Reset index after cleaning
    df.reset_index(drop=True, inplace=True)

    return df