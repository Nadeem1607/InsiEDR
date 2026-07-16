import argparse
import numpy as np
import os
import random
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)
os.environ.setdefault("TF_FORCE_GPU_ALLOW_GROWTH", "true")


IMPOSTORS_PER_USER = 200


def parse_args():
    parser = argparse.ArgumentParser(
        description="Legacy static evaluator (kept for comparability; prefer evaluate_hardened.py for paper metrics)."
    )
    parser.add_argument("dataset", help="Dataset folder name under datasets/<name>/npy/")
    parser.add_argument("--checkpoint", default="model/checkpoint.weights.h5")
    parser.add_argument("--seed", type=int, default=int(os.environ.get("TYPE2BRANCH_SEED", "42")))
    return parser.parse_args()


args = parse_args()
SEED = args.seed
random.seed(SEED)
np.random.seed(SEED)
print(f"[Repro] Seed set to {SEED}")


def configure_tf_runtime():
    """Avoid TensorFlow grabbing all VRAM at startup in shared DGX nodes."""
    try:
        import tensorflow as tf
        gpus = tf.config.list_physical_devices("GPU")
        for gpu in gpus:
            tf.config.experimental.set_memory_growth(gpu, True)
    except Exception as e:
        print(f"[TF Runtime] Memory-growth setup warning: {e}")

DATASET = args.dataset
dataset_dir = os.path.join("datasets", DATASET)
if not os.path.exists(dataset_dir):
    print(f"ERROR!!! Dataset '{DATASET}' not found at {dataset_dir}.")
    sys.exit(2)


#
# Load and verify the dataset
#

FOLDER_NPY = "datasets/" + DATASET + "/npy/";

print("Loading dataset " + DATASET + "...");
print("  Evaluation samples...");
xe = np.load(FOLDER_NPY + "xe.npy", allow_pickle=True).item();

if len(xe) == 0:
    print("ERROR: xe.npy is EMPTY (0 evaluation users).");
    print("This means the dataset split produced no test users.");
    print("Re-run ingest_aalto.py â€” the threshold has been lowered.");
    sys.exit(1);

print("  Verifying sample shapes...");
print(f"  Found {len(xe)} evaluation users.");
first_user = list(xe.keys())[0];
first_sample_id = list(xe[first_user].keys())[0];
first_sample = xe[first_user][first_sample_id];
print("    Expected shape: " + str(first_sample.shape));

SEQUENCE_LENGTH = first_sample.shape[0];
INPUT_FEATURES = first_sample.shape[1];

for user, samples in xe.items():
    for sample_id, arr in samples.items():
        if arr.shape != first_sample.shape:
            print("ERROR!!! All samples must have the same shape (found " + str(arr.shape) + " in xe.npy).");
            print("        Offender user=" + str(user) + " sample=" + str(sample_id));
            sys.exit(1);


#
# Load the model
#

descriptor = {};
descriptor["SEQUENCE_LENGTH"] = SEQUENCE_LENGTH;
descriptor["INPUT_FEATURES"] = INPUT_FEATURES;

configure_tf_runtime();
import  model;
descriptor = model.get_model_Type2Branch(descriptor, build_optimizer=False);
m = descriptor["model"];
m.summary();

checkpoint_path = args.checkpoint;
if not os.path.exists(checkpoint_path):
    print("ERROR!!! Missing model checkpoint at " + checkpoint_path);
    print("        Train first: python train.py " + DATASET);
    sys.exit(2);

print("LOAD");
m.load_weights(checkpoint_path);



#
# Calculate embeddings
#

print("Calculating embeddings...");

embeddings_by_user = {};
for user_id, samples in xe.items():
    print(".", end="", flush=True);
    user_samples = [];
    for sample_id, sample in samples.items():
        user_samples.append(sample);

    user_samples = np.stack(user_samples).astype(np.float32, copy=False);
    yl = m.predict(user_samples, verbose=0);
    embeddings_by_user[user_id] = yl;

print("");

if len(embeddings_by_user) < 2:
    print("ERROR!!! Need at least 2 evaluation users to compute impostor scores.");
    sys.exit(1);



#
# Evaluate authentication results
#

def calculate_score(gallery_samples, query_sample):
    s = 0.0;
    for gallery_sample in gallery_samples:
        d = np.linalg.norm(gallery_sample - query_sample);
        s += d;

    s /= len(gallery_samples);
    return s;



def calculate_eer(legitimate_scores, impostor_scores):
    """Calculate EER using linear sweep over thresholds for high precision."""
    all_scores = sorted(legitimate_scores + impostor_scores);
    best_thresh = 0.0;
    best_diff = float('inf');
    best_eer = 0.0;

    for thresh in np.linspace(min(all_scores), max(all_scores), 2000):
        frr = np.mean([s > thresh for s in legitimate_scores]);
        far = np.mean([s <= thresh for s in impostor_scores]);
        diff = abs(frr - far);
        if diff < best_diff:
            best_diff = diff;
            best_thresh = thresh;
            best_eer = (frr + far) / 2.0;

    return (best_thresh, best_eer * 100.0);


G = [1,2,5,7,10];

eers = {};
cumulative_sum   = {};
cumulative_count = {};
global_legitimate_scores = {};
global_impostor_scores = {};

for g in G:
    eers[g] = [];
    cumulative_count[g] = 0.0;
    cumulative_sum[g] = 0.0;
    global_legitimate_scores[g] = [];
    global_impostor_scores[g] = [];

count = -1;
for user_id, yl in embeddings_by_user.items():
    count += 1;
    print("USER " + str(user_id) + " (" + str(count) + "/" + str(len(embeddings_by_user)) + ")");

    yi = [];
    impostor_candidates = [candidate for candidate in embeddings_by_user.keys() if candidate != user_id];
    n_impostors = min(IMPOSTORS_PER_USER, len(impostor_candidates));
    impostors = random.sample(impostor_candidates, n_impostors);
    for impostor in impostors:
        yi.append(random.choice(embeddings_by_user[impostor]));

    for g in G:
        np.random.shuffle(yl);
        gallery_samples = yl[0:g];
        query_samples = yl[g:];

        legitimate_scores = [];
        for query_sample in query_samples:
            score = calculate_score(gallery_samples, query_sample);
            legitimate_scores.append(score);

        global_legitimate_scores[g].extend(legitimate_scores);
        legitimate_scores.sort();

        impostor_scores = [];
        for query_sample in yi:
            score = calculate_score(gallery_samples, query_sample);
            impostor_scores.append(score);

        global_impostor_scores[g].extend(impostor_scores);
        impostor_scores.sort();

        threshold, eer = calculate_eer(legitimate_scores, impostor_scores);
        eers[g].append(eer);
    
        cumulative_sum[g] += eer;
        cumulative_count[g] += 1.0;
        
        print("  G=" + str(g) + "    EER=" + str(eer) + "   AT " + str(threshold) + "          GLOBAL=" + str(cumulative_sum[g] / cumulative_count[g]));

print("----- GLOBAL AUTHENTICATION RESULTS");
for g in G:
    global_legitimate_scores[g].sort();
    global_impostor_scores[g].sort();
    threshold, eer = calculate_eer(global_legitimate_scores[g], global_impostor_scores[g]);
    print("G=" + str(g) + "    EER=" + str(eer) + "  AT " + str(threshold));

print("----- AVERAGED PER USER AUTHENTICATION RESULTS");
for g in G:
    eer = cumulative_sum[g] / cumulative_count[g];
    print("G=" + str(g) + "    EER=" + str(eer));

