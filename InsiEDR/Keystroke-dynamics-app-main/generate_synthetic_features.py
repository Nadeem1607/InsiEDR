import numpy as np
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ORIGINAL_CWD = os.getcwd()
os.chdir(SCRIPT_DIR)
REPO_ROOT = SCRIPT_DIR
DATASETS_ROOT = os.path.join(REPO_ROOT, "datasets")


def load_split(base_path: str, split_name: str):
    split_path = os.path.join(base_path, f"{split_name}.npy")
    if not os.path.exists(split_path):
        raise FileNotFoundError(
            f"Missing required split file: {split_path}. "
            "Run ingest_aalto.py first, or verify the dataset name."
        )
    return np.load(split_path, allow_pickle=True).item()


def calculate_population_profile(xt):
    """
    Calculates the mean HT and FT for every key (or key transition) in the training set.
    """
    print("Calculating General Population Profile...")
    
    # Store sums and counts to compute means
    # Key -> [sum_HT, count_HT]
    # (Key_prev, Key_curr) -> [sum_FT, count_FT]
    
    ht_stats = {} 
    ft_stats = {}
    
    # We need to map float keycodes back to integers or keep them as representative buckets?
    # generate_dataset.py normalizes keycode by / 255.0. 
    # To be safe, we should assume the input is the float (0.0 - 1.0).
    # We can use the float value as the key if it's consistent, or round it.
    # Let's use round(k * 255) to get back to integer ASCII for stability.
    
    user_count = 0
    for user_id, samples in xt.items():
        user_count += 1
        if user_count % 100 == 0:
            print(f"Processed {user_count} users...")
            
        for sample_id, sample in samples.items():
            # sample shape: (SEQ, 3) -> [KeyNorm, HT, FT]
            
            for i in range(len(sample)):
                key_norm = sample[i, 0]
                ht = sample[i, 1]
                ft = sample[i, 2]
                
                key_int = int(round(key_norm * 255))
                
                # Update HT stats
                if key_int not in ht_stats:
                    ht_stats[key_int] = [0.0, 0]
                ht_stats[key_int][0] += ht
                ht_stats[key_int][1] += 1
                
                # Update FT stats (requires previous key)
                if i > 0:
                    prev_key_norm = sample[i-1, 0]
                    prev_key_int = int(round(prev_key_norm * 255))
                    
                    pair = (prev_key_int, key_int)
                    if pair not in ft_stats:
                        ft_stats[pair] = [0.0, 0]
                    ft_stats[pair][0] += ft
                    ft_stats[pair][1] += 1

    # Compute Means
    profile = {}
    profile['ht'] = {k: v[0]/v[1] for k, v in ht_stats.items() if v[1] > 0}
    profile['ft'] = {k: v[0]/v[1] for k, v in ft_stats.items() if v[1] > 0}
    
    print(f"Profile computed. {len(profile['ht'])} keys, {len(profile['ft'])} transitions.")
    return profile

def augment_sample(sample, profile):
    """
    Augments a (SEQ, 3) sample to (SEQ, 5).
    Adds sHT and sFT.
    sHT = HT - Mean_HT(Key)
    sFT = FT - Mean_FT(PrevKey, Key)
    """
    seq_len = sample.shape[0]
    new_sample = np.zeros((seq_len, 5), dtype=np.float32)
    new_sample[:, :3] = np.asarray(sample[:, :3], dtype=np.float32)
    
    for i in range(seq_len):
        key_norm = sample[i, 0]
        ht = sample[i, 1]
        ft = sample[i, 2]
        key_int = int(round(key_norm * 255))
        
        # sHT
        mean_ht = profile['ht'].get(key_int, 0.1) # Default 0.1s if unknown
        sht = ht - mean_ht
        
        # sFT
        mean_ft = 0.15 # Default
        if i > 0:
            prev_key_norm = sample[i-1, 0]
            prev_key_int = int(round(prev_key_norm * 255))
            pair = (prev_key_int, key_int)
            mean_ft = profile['ft'].get(pair, 0.15)
        
        sft = ft - mean_ft
        
        new_sample[i, 3] = sht
        new_sample[i, 4] = sft
        
    return new_sample

def process_partition(name, data_dict, profile):
    print(f"Augmenting {name}...")
    new_data = {}
    for user_id, samples in data_dict.items():
        new_data[user_id] = {}
        for sample_id, sample in samples.items():
            new_data[user_id][sample_id] = augment_sample(sample, profile)
    return new_data

def main():
    if len(sys.argv) != 2:
        print("Usage: python generate_synthetic_features.py <dataset_name>")
        sys.exit(1)
        
    dataset_name = sys.argv[1]
    base_path = os.path.join(DATASETS_ROOT, dataset_name, "npy")
    
    print(f"Loading data from {base_path}...")
    try:
        xt = load_split(base_path, "xt")
        xv = load_split(base_path, "xv")
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    
    print(f"  xt: {len(xt)} users, xv: {len(xv)} users")
    
    if len(xt) == 0:
        print("ERROR: xt.npy is empty! Re-run ingest_aalto.py first.")
        sys.exit(1)
    
    # Calculate profile from Training set ONLY
    profile = calculate_population_profile(xt)
    
    # Augment
    xt_aug = process_partition("xt", xt, profile)
    xv_aug = process_partition("xv", xv, profile)
    
    # Try to load xe if exists
    try:
        xe = load_split(base_path, "xe")
        if len(xe) == 0:
            print("WARNING: xe.npy is empty (0 test users). Skipping xe augmentation.")
            xe_aug = None
        else:
            print(f"  xe: {len(xe)} users")
            xe_aug = process_partition("xe", xe, profile)
    except FileNotFoundError:
        print("No evaluation set found, skipping xe.")
        xe_aug = None

    # Save to new folder — clean old data first to prevent stale files
    out_path = os.path.join(DATASETS_ROOT, f"{dataset_name}_merged", "npy")
    import shutil
    if os.path.exists(out_path):
        shutil.rmtree(out_path)
        print(f"  Cleaned stale data at {out_path}")
    os.makedirs(out_path)
        
    print(f"Saving augmented data to {out_path}...")
    np.save(os.path.join(out_path, "xt.npy"), xt_aug, allow_pickle=True)
    np.save(os.path.join(out_path, "xv.npy"), xv_aug, allow_pickle=True)
    if xe_aug is not None:
        np.save(os.path.join(out_path, "xe.npy"), xe_aug, allow_pickle=True)
        
    print("Done.")

if __name__ == "__main__":
    main()
