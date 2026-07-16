import os
import zipfile
import glob
import sys
import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ORIGINAL_CWD = os.getcwd()
os.chdir(SCRIPT_DIR)
REPO_ROOT = SCRIPT_DIR
DATASETS_ROOT = os.path.join(REPO_ROOT, "datasets")

"""
Aalto University Keystroke Dataset Format
==========================================
Each file is named: <PARTICIPANT_ID>_keystrokes.txt
Path inside zip:    Keystrokes/files/<id>_keystrokes.txt

Columns (tab-separated, with header row):
  0: PARTICIPANT_ID
  1: TEST_SECTION_ID
  2: SENTENCE
  3: USER_INPUT
  4: KEYSTROKE_ID
  5: PRESS_TIME       â† milliseconds (Unix epoch)
  6: RELEASE_TIME     â† milliseconds (Unix epoch)
  7: LETTER
  8: KEYCODE          â† integer keycode

One file = one participant = all their keystroke sessions merged.
We chunk the full keystroke stream into SEQ_LEN=100 windows.
"""

SEQ_LEN = 100
OVERLAP  = 25
try:
    import conf  # Optional: safer default aligned with training conf.N.
    DEFAULT_MIN_SAMPLES = int(getattr(conf, "N", 15))
except Exception:
    DEFAULT_MIN_SAMPLES = 15
MIN_SAMPLES = int(os.environ.get("TYPE2BRANCH_MIN_SAMPLES", str(DEFAULT_MIN_SAMPLES)))


def resolve_existing_path(path: str) -> str:
    """
    Resolve a user-provided path against the original launch directory and the
    script directory so the script works from multiple entry points.
    """
    if os.path.isabs(path) and os.path.exists(path):
        return path

    candidates = []
    for candidate in (
        path,
        os.path.join(ORIGINAL_CWD, path),
        os.path.join(SCRIPT_DIR, path),
    ):
        norm = os.path.abspath(candidate)
        if norm not in candidates:
            candidates.append(norm)
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    raise FileNotFoundError(
        f"Could not find '{path}'. Tried: "
        + ", ".join(candidates)
    )


def stratified_user_split_by_sample_count(users, data, seed=42, val_ratio=0.10, test_ratio=0.10):
    """
    Keep sample-count distribution more balanced across xt/xv/xe splits.
    """
    if len(users) < 10:
        return users, [], []

    rng = np.random.default_rng(seed)
    counts = np.array([len(data[u]) for u in users], dtype=np.int32)
    quantiles = np.quantile(counts, [0.25, 0.50, 0.75])

    bins = {}
    for u in users:
        c = len(data[u])
        b = int(np.digitize(c, quantiles, right=True))
        bins.setdefault(b, []).append(u)

    train_users = []
    val_users = []
    test_users = []

    for b in sorted(bins.keys()):
        bucket = bins[b]
        rng.shuffle(bucket)
        n = len(bucket)
        n_test = max(1, int(round(n * test_ratio)))
        n_val = max(1, int(round(n * val_ratio)))
        if n_test + n_val >= n:
            n_test = 1
            n_val = 1
        n_train = n - n_val - n_test

        train_users.extend(bucket[:n_train])
        val_users.extend(bucket[n_train:n_train + n_val])
        test_users.extend(bucket[n_train + n_val:])

    if len(train_users) < 5:
        merged = train_users + val_users + test_users
        rng.shuffle(merged)
        n = len(merged)
        n_test = max(2, int(n * test_ratio))
        n_val = max(2, int(n * val_ratio))
        n_train = n - n_val - n_test
        train_users = merged[:n_train]
        val_users = merged[n_train:n_train + n_val]
        test_users = merged[n_train + n_val:]

    return train_users, val_users, test_users


def print_split_stats(split_name, users, data):
    if len(users) == 0:
        print(f"      {split_name}: users=0")
        return
    counts = np.array([len(data[u]) for u in users], dtype=np.int32)
    total_samples = int(np.sum(counts))
    print(
        f"      {split_name}: users={len(users)} samples={total_samples} "
        f"min={int(np.min(counts))} p50={int(np.median(counts))} "
        f"p90={int(np.percentile(counts, 90))} max={int(np.max(counts))}"
    )


def parse_aalto_file(filepath):
    """
    Parse a single <id>_keystrokes.txt file.
    Returns a list of numpy arrays, each shape (SEQ_LEN, 3): [key_norm, HT, FT]
    """
    keystrokes = []  # list of (press_ms, release_ms, keycode)

    with open(filepath, 'r', encoding='latin-1', errors='replace') as f:
        for lineno, line in enumerate(f):
            if lineno == 0:
                continue  # skip header
            line = line.strip()
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) < 9:
                continue
            try:
                press_ms   = int(parts[5])
                release_ms = int(parts[6])
                keycode    = int(parts[8])
                keystrokes.append((press_ms, release_ms, keycode))
            except (ValueError, IndexError):
                continue

    if len(keystrokes) < SEQ_LEN:
        return []  # not enough data

    # Sort by press time (sessions may be interleaved in the file)
    keystrokes.sort(key=lambda x: x[0])

    # Build feature vectors
    features = []
    for i, (p, r, k) in enumerate(keystrokes):
        k_norm = min(k, 255) / 255.0          # normalised keycode 0-1
        ht     = min((r - p) / 1000.0, 1.0)   # hold-time in seconds, clipped
        # Flight-time: press[i] - press[i-1]  (inter-press interval)
        ft = 0.0
        if i > 0:
            ft = min((p - keystrokes[i-1][0]) / 1000.0, 1.0)
        features.append([k_norm, ht, ft])

    # Sliding-window chunks
    samples = []
    for start in range(0, len(features) - SEQ_LEN + 1, OVERLAP):
        chunk = features[start : start + SEQ_LEN]
        samples.append(np.array(chunk, dtype=np.float32))   # (100, 3)

    return samples


def save_npy(user_list, all_data, dataset_name, suffix):
    final_dict = {}
    for u in user_list:
        final_dict[u] = all_data[u]

    save_path = os.path.join(DATASETS_ROOT, dataset_name, "npy")
    os.makedirs(save_path, exist_ok=True)
    np.save(os.path.join(save_path, f"{suffix}.npy"), final_dict, allow_pickle=True)
    n_samples = sum(len(v) for v in final_dict.values())
    print(f"  Saved {suffix}.npy  ({len(user_list)} users, {n_samples} samples)")


def process_aalto_zip(zip_path, output_dataset_name="aalto_desktop"):
    """
    Extract Keystrokes.zip, parse every *_keystrokes.txt inside
    Keystrokes/files/, and save train/val/test .npy files.
    """
    zip_path = resolve_existing_path(zip_path)
    extract_dir = os.path.join(REPO_ROOT, "temp_aalto_extract")

    output_dir = os.path.join(DATASETS_ROOT, output_dataset_name, "npy")
    os.makedirs(output_dir, exist_ok=True)

    print(f"[1/4] Extracting {zip_path}  ({os.path.getsize(zip_path)//1_000_000} MB)...")
    with zipfile.ZipFile(zip_path, 'r') as zf:
        # List all matching members regardless of exact subfolder depth
        members = [m for m in zf.namelist()
                   if m.lower().endswith('_keystrokes.txt')]
        print(f"      Found {len(members)} *_keystrokes.txt entries in zip.")
        zf.extractall(extract_dir)

    # Find all extracted txt files
    txt_files = glob.glob(
        os.path.join(extract_dir, "**", "*_keystrokes.txt"), recursive=True
    )
    print(f"[2/4] Parsing {len(txt_files)} files...")

    data        = {}   # user_id â†’ { "S0": array, "S1": array, ... }
    parse_ok    = 0
    parse_skip  = 0

    for file_path in txt_files:
        filename = os.path.basename(file_path)
        # Filename: <PARTICIPANT_ID>_keystrokes.txt
        user_id  = filename.split('_')[0]

        try:
            samples = parse_aalto_file(file_path)
        except Exception as e:
            print(f"  [WARN] {filename}: {e}")
            parse_skip += 1
            continue

        if len(samples) == 0:
            parse_skip += 1
            continue

        parse_ok += 1
        if user_id not in data:
            data[user_id] = {}
        start = len(data[user_id])
        for i, s in enumerate(samples):
            data[user_id][f"S{start+i}"] = s

    print(f"      Parsed OK: {parse_ok}  Skipped: {parse_skip}")
    print(f"      Total users before filtering: {len(data)}")

    # â”€â”€ Filter: keep users with at least MIN_SAMPLES chunks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    valid_users = [u for u in data if len(data[u]) >= MIN_SAMPLES]
    discarded   = len(data) - len(valid_users)
    print(f"      Valid users (>= {MIN_SAMPLES} samples): {len(valid_users)}  "
          f"Discarded: {discarded}")

    if len(valid_users) < 10:
        print(f"\n  !! WARNING: Only {len(valid_users)} valid users found.")
        print( "     Sample counts for first 20 users:")
        for u in list(data.keys())[:20]:
            print(f"       User {u}: {len(data[u])} samples")

    # â”€â”€ Reproducible train / val / test split â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    train_users, val_users, test_users = stratified_user_split_by_sample_count(
        valid_users, data, seed=42, val_ratio=0.10, test_ratio=0.10
    )

    if len(train_users) < 5:
        print(f"\n  !! CRITICAL: Only {len(train_users)} training users - results will be unreliable.")

    print(f"[3/4] Split -> Train: {len(train_users)}  Val: {len(val_users)}  Test: {len(test_users)}")
    print("      Split balance summary:")
    print_split_stats("Train", train_users, data)
    print_split_stats("Val", val_users, data)
    print_split_stats("Test", test_users, data)

    # â”€â”€ Save â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print(f"[4/4] Saving to {output_dir} ...")
    save_npy(train_users, data, output_dataset_name, "xt")
    save_npy(val_users,   data, output_dataset_name, "xv")
    save_npy(test_users,  data, output_dataset_name, "xe")

    # Cleanup
    import shutil
    shutil.rmtree(extract_dir, ignore_errors=True)
    print(f"      Cleaned up {extract_dir}/")
    print("Done! âœ“")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ingest_aalto.py <path_to_Keystrokes.zip>")
        sys.exit(1)
    try:
        process_aalto_zip(sys.argv[1])
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    except zipfile.BadZipFile as e:
        print(f"ERROR: Invalid zip archive: {e}")
        sys.exit(1)


