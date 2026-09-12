"""
promote_confirmed_malicious.py

Takes URLs from data/auto_logged_malicious.csv (logged automatically when
BOTH the ML ensemble AND Gemini agreed a URL is malicious) and promotes
them into data/raw_urls.csv as label=1 training rows.

Safe to re-run: backs up raw_urls.csv first, skips URLs already present
in raw_urls.csv, and clears out only the entries it successfully promoted
(so re-running won't double-add anything).
"""

import pandas as pd
import shutil
import os
from datetime import datetime

RAW_URLS_PATH = "../data/raw_urls.csv"
LOG_PATH = "../data/auto_logged_malicious.csv"

def main():
    if not os.path.exists(LOG_PATH):
        print("No auto_logged_malicious.csv found — nothing to promote yet.")
        return

    log_df = pd.read_csv(LOG_PATH)
    if len(log_df) == 0:
        print("Log file is empty — nothing to promote.")
        return

    print(f"Found {len(log_df)} confirmed-malicious entries in the log.")

    # ── Backup raw_urls.csv first ──
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"../data/raw_urls_backup_{timestamp}.csv"
    shutil.copy(RAW_URLS_PATH, backup_path)
    print(f"✅ Backup saved: {backup_path}")

    # ── Load raw_urls.csv, check for duplicates ──
    raw_df = pd.read_csv(RAW_URLS_PATH)
    existing_urls = set(raw_df["url"].astype(str).str.lower())

    new_rows = []
    promoted_urls = []
    for _, row in log_df.iterrows():
        url = str(row["url"])
        if url.lower() in existing_urls:
            print(f"⚠️  Skipping (already in raw_urls.csv): {url}")
            promoted_urls.append(url)  # still clear it from the log either way
            continue
        new_rows.append({"url": url, "label": 1})
        promoted_urls.append(url)
        existing_urls.add(url.lower())

    if new_rows:
        new_df = pd.DataFrame(new_rows)
        raw_df_updated = pd.concat([raw_df, new_df], ignore_index=True)
        raw_df_updated.to_csv(RAW_URLS_PATH, index=False)
        print(f"✅ Promoted {len(new_rows)} new malicious URLs into raw_urls.csv:")
        for row in new_rows:
            print(f"   {row['url']}")
        print(f"New raw_urls.csv size: {len(raw_df_updated):,} rows")
    else:
        print("No new URLs to add (all were already present).")

    # ── Clear promoted entries from the log so re-running doesn't double-add ──
    remaining_log = log_df[~log_df["url"].astype(str).isin(promoted_urls)]
    remaining_log.to_csv(LOG_PATH, index=False)
    print(f"\n✅ Log file cleared of promoted entries. "
          f"{len(remaining_log)} unpromoted entries remain (if any).")

    print("\nNext: run step2_features.ipynb, then step3_imbalance.ipynb,")
    print("then step4_training.ipynb, then step7_evaluation.ipynb — in that order.")

if __name__ == "__main__":
    main()