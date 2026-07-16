import  conf;
import  matplotlib
matplotlib.use('Agg')  # Non-interactive backend (DGX has no display)
import  matplotlib.pyplot       as plt;
import  numpy                   as np;
import  os;
import  random;
import  shutil;
import  sys;
import  tensorflow              as tf;
import  math;
from    datetime                import datetime;

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__));
os.chdir(SCRIPT_DIR);

SEED = int(os.environ.get("TYPE2BRANCH_SEED", "42"));
random.seed(SEED);
np.random.seed(SEED);
tf.random.set_seed(SEED);
print(f"[Repro] Seed set to {SEED}");

# =============================================================
#  DGX H200 Optimization: Mixed Precision (FP16)
#  Doubles throughput on Tensor Cores with negligible accuracy loss
# =============================================================
MIXED_PRECISION = os.environ.get("TYPE2BRANCH_MIXED_PRECISION", "1") == "1";
if MIXED_PRECISION:
    try:
        policy = tf.keras.mixed_precision.Policy('mixed_float16')
        tf.keras.mixed_precision.set_global_policy(policy)
        print("[DGX] Mixed Precision ENABLED (float16 compute, float32 storage)")
    except Exception as e:
        print(f"[DGX] Mixed Precision not available: {e}")
else:
    print("[DGX] Mixed Precision DISABLED (TYPE2BRANCH_MIXED_PRECISION=0)");


# =============================================================
#  GPU Memory Growth (prevents OOM on multi-GPU systems)
# =============================================================
gpus = tf.config.list_physical_devices('GPU')
if gpus:
    try:
        for gpu in gpus:
            tf.config.experimental.set_memory_growth(gpu, True)
        print(f"[DGX] {len(gpus)} GPU(s) detected. Memory growth enabled.")
    except RuntimeError as e:
        print(f"[DGX] GPU config error: {e}")



def print_help():
    print("train.py {dataset}");
    exit(-1);


def quick_finite_scan(partition_name, data, max_users, max_samples):
    users = list(data.keys())[: min(len(data), max_users)];
    scanned_users = 0;
    scanned_samples = 0;

    for user in users:
        for sample_id, arr in data[user].items():
            if not np.all(np.isfinite(arr)):
                bad_values = int(arr.size - np.count_nonzero(np.isfinite(arr)));
                print(
                    "ERROR!!! Non-finite values found in "
                    f"{partition_name}.npy (user={user}, sample={sample_id}, invalid_values={bad_values})."
                );
                sys.exit(1);

            scanned_samples += 1;
            if scanned_samples >= max_samples:
                break;

        scanned_users += 1;
        if scanned_samples >= max_samples:
            break;

    print(
        f"    Finite-value scan passed for {partition_name}.npy "
        f"(scanned_users={scanned_users}, scanned_samples={scanned_samples})."
    );
    

#
# Verify command line parameters
#

if len(sys.argv) != 2:
    print_help();
if not os.path.exists("datasets/" + sys.argv[1] + "/"):
    print("ERROR!!! Dataset '" + sys.argv[1] + "' not found.");
    print_help();

DATASET = sys.argv[1];


#
# Load and verify the dataset
#

FOLDER_NPY = "datasets/" + DATASET + "/npy/";

print("Loading dataset " + DATASET + "...");
print("  Training samples...");
xt = np.load(FOLDER_NPY + "xt.npy", allow_pickle=True).item();
print("  Validation samples...");
xv = np.load(FOLDER_NPY + "xv.npy", allow_pickle=True).item();

if len(xt) == 0:
    print("ERROR!!! xt.npy is empty.");
    sys.exit(1);
if len(xv) == 0:
    print("ERROR!!! xv.npy is empty.");
    sys.exit(1);

print("  Verifying sample shapes...");
first_user = list(xt.keys())[0];
first_sample_id = list(xt[first_user].keys())[0];
first_sample = xt[first_user][first_sample_id];
print("    Expected shape: " + str(first_sample.shape));

SEQUENCE_LENGTH = first_sample.shape[0];
INPUT_FEATURES = first_sample.shape[1];

for user, samples in xt.items():
    for sample_id, arr in samples.items():
        if arr.shape != first_sample.shape:
            print("ERROR!!! All samples must have the same shape (found " + str(arr.shape) + " in xt.npy).");
            print("        Offender user=" + str(user) + " sample=" + str(sample_id));
            sys.exit(1);

for user, samples in xv.items():
    for sample_id, arr in samples.items():
        if arr.shape != first_sample.shape:
            print("ERROR!!! All samples must have the same shape (found " + str(arr.shape) + " in xv.npy).");
            print("        Offender user=" + str(user) + " sample=" + str(sample_id));
            sys.exit(1);

FINITE_SCAN_USERS = int(os.environ.get("TYPE2BRANCH_FINITE_SCAN_USERS", "4000"));
FINITE_SCAN_SAMPLES = int(os.environ.get("TYPE2BRANCH_FINITE_SCAN_SAMPLES", "100000"));
print(
    "  Finite-value quick scan (set TYPE2BRANCH_FINITE_SCAN_USERS / "
    "TYPE2BRANCH_FINITE_SCAN_SAMPLES to tune)..."
);
quick_finite_scan("xt", xt, FINITE_SCAN_USERS, FINITE_SCAN_SAMPLES);
quick_finite_scan("xv", xv, FINITE_SCAN_USERS, FINITE_SCAN_SAMPLES);



#
# Initialize the training and validation generators
#

descriptor = {};
descriptor["SEQUENCE_LENGTH"] = SEQUENCE_LENGTH;
descriptor["INPUT_FEATURES"] = INPUT_FEATURES;

print("Initializing generators...");
print("  N (samples per user):        " + str(conf.N));
print("  K (sets per batch):          " + str(conf.K));
print("  Sample length (keystrokes):  " + str(SEQUENCE_LENGTH));
print("  Input features:              " + str(INPUT_FEATURES));

print("  Initializing training generator...");
import  training_generator;
ti, tg, tc = training_generator.get_generator(descriptor, xt);

print("  Initializing validation generator...");
import  validation_generator;
vi, vg, vc = validation_generator.get_generator(descriptor, xv);


#
# Initialize loss function
#

print("Initializing loss function...");
import  loss;
l = loss.get_loss();


#
# Compile the model
#

os.makedirs("model", exist_ok=True);
checkpoint_path = "model/checkpoint.weights.h5";
if os.path.exists(checkpoint_path):
    backup_path = "model/checkpoint.weights.pretrain." + datetime.now().strftime("%Y%m%d_%H%M%S") + ".h5";
    shutil.copy2(checkpoint_path, backup_path);
    print("Found existing checkpoint. Backed up to: " + backup_path);

import  model;
descriptor = model.get_model_Type2Branch(descriptor);
m = descriptor["model"];
m.summary();

m.compile(
    optimizer=descriptor["optimizer"],
    loss=l,
);

#
# Initialize callbacks
#

class SaveModelFromEpochCallback(tf.keras.callbacks.ModelCheckpoint):
    def __init__(self, filepath, save_start_epoch=10, **kwargs):
        super(SaveModelFromEpochCallback, self).__init__(filepath, **kwargs)
        self.save_start_epoch = save_start_epoch

    def on_epoch_end(self, epoch, logs=None):
        if epoch >= self.save_start_epoch:
            super(SaveModelFromEpochCallback, self).on_epoch_end(epoch, logs)


# Paper Sec IV-A: "No scheduling is used; the learning rate is kept
# fixed throughout the entire training process." (LR = 1e-4)

print("Initializing callbacks...");
callbacks = [
    tf.keras.callbacks.TerminateOnNaN(),
    SaveModelFromEpochCallback(
        checkpoint_path,
        save_start_epoch        = 0,
        monitor                 = "val_loss",
        save_best_only          = True,
        save_weights_only       = True,
        verbose                 = 2),
    tf.keras.callbacks.EarlyStopping(
        monitor="val_loss",
        min_delta=0.0001,
        restore_best_weights=True,
        patience=conf.EARLY_STOP_PATIENCE),
    # TensorBoard for real-time training visualization
    tf.keras.callbacks.TensorBoard(
        log_dir="logs/",
        histogram_freq=5,
        update_freq='epoch'),
];

if tc != None:
    callbacks.append(tc);
if vc != None:
    callbacks.append(vc);


#
# Train the model
#

print("Training model...");
auto_validation_steps = max(1, len(xv) // conf.K);
validation_steps = int(os.environ.get("TYPE2BRANCH_VALIDATION_STEPS", str(auto_validation_steps)));
if validation_steps <= 0:
    print("ERROR!!! TYPE2BRANCH_VALIDATION_STEPS must be >= 1.");
    sys.exit(1);
print(f"  Epochs: {conf.EPOCHS}");
print(f"  Steps/Epoch: {conf.TRAINING_STEPS}");
print(f"  Val Steps: {validation_steps} (auto={auto_validation_steps}, users={len(xv)}, K={conf.K})");
print(f"  Total Batches: {conf.EPOCHS * conf.TRAINING_STEPS}");

history = descriptor["model"].fit(
    ti,
    validation_data     = vi,
    epochs              = conf.EPOCHS,                    
    steps_per_epoch     = conf.TRAINING_STEPS,
    validation_steps    = validation_steps,
    callbacks           = callbacks,
    verbose             = 2,
);

if not os.path.exists(checkpoint_path):
    print("ERROR!!! Training ended without checkpoint at " + checkpoint_path);
    print("        This usually means val_loss never improved or training failed.");
    sys.exit(1);

print("Best checkpoint available at: " + checkpoint_path);



#
# Save the loss history
#

plt.figure(figsize=(14, 5))

plt.subplot(1, 3, 1)
plt.plot(history.history['loss'], label='Train Loss', color='#2196F3', linewidth=2)
plt.plot(history.history['val_loss'], label='Val Loss', color='#F44336', linewidth=2)
plt.title('Model Loss', fontsize=14, fontweight='bold')
plt.ylabel('Loss')
plt.xlabel('Epoch')
plt.legend(loc='upper right')
plt.grid(True, alpha=0.3)

plt.subplot(1, 3, 2)
if 'lr' in history.history:
    plt.plot(history.history['lr'], label='Learning Rate', color='#4CAF50', linewidth=2)
    plt.title('Learning Rate Schedule', fontsize=14, fontweight='bold')
    plt.ylabel('Learning Rate')
    plt.xlabel('Epoch')
    plt.legend(loc='upper right')
    plt.grid(True, alpha=0.3)
    plt.yscale('log')

plt.subplot(1, 3, 3)
# Plot train vs val loss gap (overfitting indicator)
gap = np.array(history.history['val_loss']) - np.array(history.history['loss'])
plt.plot(gap, label='Val-Train Gap', color='#FF9800', linewidth=2)
plt.axhline(y=0, color='black', linestyle='--', alpha=0.3)
plt.title('Overfitting Monitor', fontsize=14, fontweight='bold')
plt.ylabel('Val Loss - Train Loss')
plt.xlabel('Epoch')
plt.legend(loc='upper right')
plt.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig("LOSS.png", dpi=150);
print("Saved LOSS.png");
