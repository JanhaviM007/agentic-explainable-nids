"""
Download and Cache Official MITRE Enterprise ATT&CK STIX 2.1 Bundle.

Fetches the latest enterprise-attack.json from the official mitre-attack/attack-stix-data
GitHub repository into data/mitre/enterprise-attack.json with local caching.
"""

import argparse
import json
import logging
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("download_mitre")

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "mitre"
DEST_FILE = DATA_DIR / "enterprise-attack.json"


def download_enterprise_attack(
    dest_path: Optional[Path] = None,
    force: bool = False,
    timeout: int = 120
) -> Path:
    """
    Downloads enterprise-attack.json from the official repository if not already cached.

    Args:
        dest_path: Target file path (defaults to data/mitre/enterprise-attack.json).
        force: If True, re-downloads even if cached file exists.
        timeout: Network timeout in seconds.

    Returns:
        Path to the downloaded/cached STIX JSON file.
    """
    target = Path(dest_path or DEST_FILE)
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists() and target.stat().st_size > 1_000_000 and not force:
        size_mb = target.stat().st_size / (1024 * 1024)
        logger.info("Found cached MITRE Enterprise ATT&CK bundle at %s (%.1f MB). Skipping download.", target, size_mb)
        return target

    logger.info("Downloading official MITRE Enterprise ATT&CK bundle from %s...", MITRE_STIX_URL)
    temp_target = target.with_suffix(".tmp")
    start_time = time.perf_counter()

    try:
        req = urllib.request.Request(
            MITRE_STIX_URL,
            headers={"User-Agent": "NIDS-Agentic-System/1.0 (Educational Academic Project)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            total_size = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 1024 * 1024  # 1 MB

            with open(temp_target, "wb") as out_file:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    out_file.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        logger.info("Downloaded %.1f / %.1f MB (%.1f%%)", downloaded / (1024 * 1024), total_size / (1024 * 1024), percent)

        # Atomic replacement
        if target.exists():
            target.unlink()
        temp_target.rename(target)

        elapsed = time.perf_counter() - start_time
        final_size_mb = target.stat().st_size / (1024 * 1024)
        logger.info("Successfully cached MITRE ATT&CK STIX bundle at %s (%.1f MB in %.1fs)", target, final_size_mb, elapsed)
        return target

    except Exception as e:
        if temp_target.exists():
            temp_target.unlink()
        logger.error("Failed to download MITRE STIX bundle: %s", str(e))
        raise RuntimeError(f"Could not download MITRE ATT&CK STIX bundle: {str(e)}") from e


def main():
    parser = argparse.ArgumentParser(description="Download official MITRE Enterprise ATT&CK STIX bundle.")
    parser.add_argument("--force", action="store_true", help="Force re-download even if already cached.")
    parser.add_argument("--dest", type=str, default=str(DEST_FILE), help="Custom target file path.")
    args = parser.parse_args()

    try:
        path = download_enterprise_attack(dest_path=Path(args.dest), force=args.force)
        print(f"\n[OK] MITRE STIX bundle ready at: {path}")
    except Exception as err:
        print(f"\n[ERROR] Download failed: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
