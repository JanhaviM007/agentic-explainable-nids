import pandas as pd
from pathlib import Path


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "CICIDS2017"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "CICIDS2017_final"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)


def remove_global_duplicates():

    processed_files = sorted(
        INPUT_DIR.glob("*.csv")
    )

    print(f"Found {len(processed_files)} files.")

    # Stores fingerprints of rows already seen
    seen_hashes = set()

    total_rows = 0
    total_duplicates = 0
    total_kept = 0

    for input_file in processed_files:

        output_file = (
            OUTPUT_DIR /
            input_file.name.replace(
                "_cleaned.csv",
                "_final.csv"
            )
        )

        print("\n" + "=" * 70)
        print(f"Processing: {input_file.name}")

        first_chunk = True

        file_rows = 0
        file_duplicates = 0
        file_kept = 0

        for chunk in pd.read_csv(
            input_file,
            chunksize=100_000
        ):

            chunk.columns = chunk.columns.str.strip()

            file_rows += len(chunk)

            # Create fingerprint for every row
            hashes = pd.util.hash_pandas_object(
                chunk,
                index=False
            )

            # Keep only rows whose fingerprint
            # has not been seen before
            keep_mask = []

            for h in hashes:
                h = int(h)

                if h in seen_hashes:
                    keep_mask.append(False)
                    file_duplicates += 1
                else:
                    seen_hashes.add(h)
                    keep_mask.append(True)

            cleaned_chunk = chunk.loc[
                keep_mask
            ]

            file_kept += len(cleaned_chunk)

            # Save
            cleaned_chunk.to_csv(
                output_file,
                mode="w" if first_chunk else "a",
                header=first_chunk,
                index=False
            )

            first_chunk = False

        total_rows += file_rows
        total_duplicates += file_duplicates
        total_kept += file_kept

        print(f"Rows before:      {file_rows:,}")
        print(f"Duplicates:       {file_duplicates:,}")
        print(f"Rows kept:        {file_kept:,}")

    print("\n" + "=" * 70)
    print("GLOBAL DUPLICATE REMOVAL COMPLETE")
    print("=" * 70)

    print(f"Total rows:        {total_rows:,}")
    print(f"Total duplicates:  {total_duplicates:,}")
    print(f"Total rows kept:   {total_kept:,}")

    print(f"\nSaved to:")
    print(OUTPUT_DIR)


if __name__ == "__main__":
    remove_global_duplicates()