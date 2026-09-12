"""
add_new_safe_urls.py

Appends confirmed-legitimate URLs (found via real-world testing) to
raw_urls.csv as label=0 (SAFE) rows. Run this once, then re-run the
pipeline in order: step2_features -> step3_imbalance -> step4_training
-> step7_evaluation.

A timestamped backup of raw_urls.csv is made first, so this is safe
to re-run or undo if needed.
"""

import pandas as pd
import shutil
from datetime import datetime

RAW_URLS_PATH = "../data/raw_urls.csv"

# Real domains confirmed as false positives during live testing tonight —
# genuinely legitimate sites the model wrongly flagged as malicious.
# (Deliberately excludes: private IPs, invented/example test domains, and
# heavily-parameterized tracking URLs — see conversation notes on why.)
NEW_SAFE_URLS = [
    "biet.ac.in",
    "huggingface.co",
    "quora.com",
    "coursera.org",
    "scrimba.com",
    "propeers.in",
]

def main():
    # ── Backup first ──
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"../data/raw_urls_backup_{timestamp}.csv"
    shutil.copy(RAW_URLS_PATH, backup_path)
    print(f"✅ Backup saved: {backup_path}")

    # ── Load, check for duplicates, append ──
    df = pd.read_csv(RAW_URLS_PATH)
    print(f"Current dataset size: {len(df):,} rows")

    existing_urls = set(df["url"].astype(str).str.lower())
    new_rows = []
    for url in NEW_SAFE_URLS:
        if url.lower() in existing_urls:
            print(f"⚠️  Skipping (already in dataset): {url}")
            continue
        new_rows.append({"url": url, "label": 0})

    if not new_rows:
        print("Nothing new to add — all URLs already present.")
        return

    new_df = pd.DataFrame(new_rows)
    df_updated = pd.concat([df, new_df], ignore_index=True)
    df_updated.to_csv(RAW_URLS_PATH, index=False)

    print(f"✅ Added {len(new_rows)} new SAFE URLs:")
    for row in new_rows:
        print(f"   {row['url']}")
    print(f"\nNew dataset size: {len(df_updated):,} rows")
    print("\nNext steps: run step2_features.ipynb, then step3_imbalance.ipynb,")
    print("then step4_training.ipynb, then step7_evaluation.ipynb — in that order.")

if __name__ == "__main__":
    main()