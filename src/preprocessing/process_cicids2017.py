import pandas as pd
from pathlib import Path
import sys

# Allow importing from src
sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.preprocessing.clean_cicids2017 import clean_dataframe


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]

RAW_DIR = PROJECT_ROOT / "data" / "raw" / "CICIDS2017"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed" / "CICIDS2017"

PROCESSED_DIR.mkdir(
    parents=True,
    exist_ok=True
)


def process_file(input_file: Path, output_file: Path):
    """
    Process one CICIDS2017 CSV file in chunks.
    """

    print(f"\nProcessing: {input_file.name}")

    first_chunk = True
    total_before = 0
    total_after = 0

    for chunk in pd.read_csv(
        input_file,
        chunksize=100_000
    ):
        total_before += len(chunk)

        cleaned_chunk = clean_dataframe(chunk)

        total_after += len(cleaned_chunk)

        cleaned_chunk.to_csv(
            output_file,
            mode="w" if first_chunk else "a",
            header=first_chunk,
            index=False
        )

        first_chunk = False

    print(f"Rows before cleaning: {total_before:,}")
    print(f"Rows after cleaning:  {total_after:,}")
    print(f"Rows removed:         {total_before - total_after:,}")
    print(f"Saved to: {output_file}")


def main():

    csv_files = sorted(RAW_DIR.glob("*.csv"))

    print(f"Found {len(csv_files)} CSV files.")

    for input_file in csv_files:

        output_file = (
            PROCESSED_DIR /
            f"{input_file.stem}_cleaned.csv"
        )

        process_file(
            input_file,
            output_file
        )


if __name__ == "__main__":
    main()