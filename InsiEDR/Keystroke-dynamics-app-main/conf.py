# Number of samples per user/set
N = 15;

# Number of sets per batch
# Paper: K=40 on A100 40GB. H200 has 80GB+, so K=40 fits comfortably.
# Fig. 5 in paper shows larger K → lower EER.
K = 40;

#
# CURRICULUM_DELAY
#   Number of epochs it takes the curriculum to add one nearest neighbour.
#   The curriculum delay should grow with a diminishing number of users in the dataset. The exact value should be optimized empirically.
#   For 1K users, 20 is optimal. For the maximum number of users (113K in the KVC dataset), CURRICULUM_DELAY = 1 is best.
#
# Example: 
#   CURRICULUM_DELAY = 1
#       EPOCH 0 - Only random neighbours
#       EPOCH 1 - 1 nearest neighbour, K - 1 random 
#       EPOCH 2 - 2 nearest neighbour, K - 2 random 
#       etc.
#   CURRICULUM_DELAY = 10
#       EPOCH 0-9   - Only random neighbours
#       EPOCH 10-19 - 1 nearest neighbour, K - 1 random 
#       EPOCH 20-29 - 2 nearest neighbour, K - 2 random 
#       etc.

CURRICULUM_DELAY = 5;   # Reduced: with K=40 we have more classes per batch, so curriculum ramps faster

#
# CURRICULUM_MAX_NEIGHBOURS
#   Maximum number of nearest neighbours in batch.
#   It should never exceed K - 2.
#   It is generally optimal with values around (K-2)/2.
#
# Example:
#   CURRICULUM_DELAY = 1, CURRICULUM_MAX_NEIGHBOURS = 2
#       EPOCH 0 - Only random neighbours
#       EPOCH 1 - 1 nearest neighbour, K - 1 random 
#       EPOCH 2 - 2 nearest neighbour, K - 2 random 
#       EPOCH 3 - 2 nearest neighbour, K - 2 random (hit CURRICULUM_MAX_NEIGHBOURS = 2 limitation)
#       EPOCH 4 - 2 nearest neighbour, K - 2 random (hit CURRICULUM_MAX_NEIGHBOURS = 2 limitation)

CURRICULUM_MAX_NEIGHBOURS = 19;  # Paper: optimal ≈ (K-2)/2 = (40-2)/2 = 19

#
# Model hyperparameters
#
#     MODEL_DROPOUT - Uniform value of dropout for the entire model. If you prefer to fine-tune each dropout layer, you will have to change model.py.
#     MODEL_WIDTH   - Uniform width of the recurrent layers. If you prefer to fine-tune the width of each recurrent layer, you will have to change model.py.
#     MODEL_FILTERS - Number of filters in the first convolutional layer; the other two have 2 * MODEL_FILTERS and 4 * MODEL_FILTERS. If you prefer [..., etc.]

MODEL_DROPOUT = 0.3;
MODEL_WIDTH   = 512;   # Full model — matches local checkpoint.weights.h5
MODEL_FILTERS = 256;   # Full model — matches local checkpoint.weights.h5
 
# Set2Set loss hyperparameter
# Paper Fig. 6: β=0.05 is optimal. Higher values crush embedding space.
BETA = 0.05;

#
# TRAINING_STEPS
#   Number of batches per epoch.
#   If TRAINING_STEPS is too small, the centroids are recalculated too often and the network is prematurely exposed to nearest neighbours only,
#   thus worsening the training outcome. If TRAINING_STEPS is too large, the centroids are recalculate too unfrequently and the network is
#   exposed to obsolete centroid statistics, thus worsening the training outcome again. Most often,
#
#       TRAINING_STEPS = U / sqrt(K)
#
#   should be near optimal, but this needs to be determined empirically.

TRAINING_STEPS   = 5000;  # Fast run: 5,000 steps (was 20000)

#
# The datasets generated with the generate_dataset.py script included here always have 1000 validation users. Thus, VALIDATION_STEPS should be
#
#     VALIDATION_STEPS = floor(1000/K)
#
# If you build training/validation datasets yourself, replace the 1000 value in the equation above with the number of validation users.

VALIDATION_STEPS = 25;   # floor(val_users / K). Adjusted for K=40.

#
# Training termination
#   EPOCHS - Maximum number of training epochs.
#   EARLY_STOP_PATIENCE - Maximum number of epoch without val_loss improvement.

EPOCHS = 8000;

EARLY_STOP_THRESHOLD = 0.8; # Stricter threshold
EARLY_STOP_PATIENCE  = 5;  # Fast run: patience=5 (was 12)