import  math;
import  numpy       as np;
import  os;
import  random;
import  tensorflow  as tf;

import  conf;


def calculate_centroids(model, user_cache, users, users_per_chunk=1024):
    """Calculate centroid embedding per user with chunked batched inference."""
    predict_batch_size = int(os.environ.get("TYPE2BRANCH_CENTROID_PREDICT_BATCH", "256"));
    if predict_batch_size < 1:
        raise ValueError("TYPE2BRANCH_CENTROID_PREDICT_BATCH must be >= 1.");

    centroids = {};
    invalid_users = set();
    total = len(users);
    chunks = int(math.ceil(total / float(users_per_chunk)));

    for chunk_idx in range(chunks):
        start = chunk_idx * users_per_chunk;
        end = min(start + users_per_chunk, total);
        chunk_users = users[start:end];

        # Shape: [len(chunk_users) * N, SEQ, FEAT]
        batch = np.concatenate([user_cache[u] for u in chunk_users], axis=0).astype(np.float32, copy=False);
        embs = model.predict(batch, verbose=0, batch_size=predict_batch_size);
        embs = np.asarray(embs, dtype=np.float32);

        # Restore user grouping and average each user's N samples.
        expected_rows = len(chunk_users) * conf.N;
        if embs.shape[0] != expected_rows:
            raise ValueError(
                f"Centroid inference returned {embs.shape[0]} rows, expected {expected_rows}. "
                "Check generator/model output shape alignment."
            );
        embs = embs.reshape(len(chunk_users), conf.N, -1);
        means = np.mean(embs, axis=1, dtype=np.float32);
        finite_mask = np.all(np.isfinite(means), axis=1);

        for i, user_id in enumerate(chunk_users):
            if finite_mask[i]:
                centroids[user_id] = means[i];
            else:
                invalid_users.add(user_id);

        if (chunk_idx + 1) % 10 == 0 or chunk_idx == chunks - 1:
            print(
                f"[CurriculumSets] Centroids {end}/{total} users computed..."
                f" (invalid={len(invalid_users)})"
            );

    return centroids, invalid_users;



class CurriculumSetsGenerator:
    def __init__(self, descriptor, x, K, delay, max_neighbours):
        self.descriptor = descriptor;
        self.x = x;
        self.K = K;
        self.delay = delay;
        self.max_neighbours = max_neighbours;

        self.epoch = 0;
        self.users = list(x.keys());
        if len(self.users) < self.K:
            raise ValueError(
                f"CurriculumSetsGenerator requires at least K users (K={self.K}, users={len(self.users)}). "
                "Lower conf.K or ingest more users."
            );
        self.centroids = None;
        self.tree = None;
        self.tree_users = [];
        self.tree_user_set = set();
    
    
    def initialize(self):
        """Cache full per-user pools and prepare an epoch-specific N-sample cache."""
        self.user_samples = {};
        self.user_cache = {};
        for user_id, samples in self.x.items():
            sample_list = [np.asarray(s, dtype=np.float32) for s in samples.values()];
            self.user_samples[user_id] = np.stack(sample_list, axis=0);
        self.refresh_user_cache();
        print(f"    Cached sample pools for {len(self.user_samples)} users.");


    def refresh_user_cache(self):
        """Re-sample N examples per user each epoch to reduce fixed-sample bias."""
        for user_id, sample_pool in self.user_samples.items():
            total = sample_pool.shape[0];
            replace = total < conf.N;
            picked = np.random.choice(total, size=conf.N, replace=replace);
            self.user_cache[user_id] = sample_pool[picked];


    def on_epoch_end(self, epoch, logs=None):
        pass;

    def on_epoch_begin(self, epoch, logs=None):
        print("[CurriculumSets] EPOCH " + str(epoch));
        self.epoch = epoch;
        self.refresh_user_cache();

        if self.epoch < self.delay:
            print("[CurriculumSets] Naive training without challenge.");
        else:
            print("[CurriculumSets] Calculating user centroids...");
            self.centroids, invalid_users = calculate_centroids(self.descriptor["model"], self.user_cache, self.users);
            self.tree = None;
            self.tree_users = [u for u in self.users if u in self.centroids];
            self.tree_user_set = set(self.tree_users);
            if len(self.tree_users) < 2:
                print(
                    "[CurriculumSets] WARNING: Too few finite centroids for curriculum "
                    f"({len(self.tree_users)} finite, {len(invalid_users)} invalid). Falling back to random sets."
                );
                return;

            indexed_centroids = np.asarray([self.centroids[u] for u in self.tree_users], dtype=np.float32);
            finite_rows = np.all(np.isfinite(indexed_centroids), axis=1);
            if not np.all(finite_rows):
                self.tree_users = [u for u, keep in zip(self.tree_users, finite_rows) if keep];
                indexed_centroids = indexed_centroids[finite_rows];
                self.tree_user_set = set(self.tree_users);
                if len(self.tree_users) < 2:
                    print(
                        "[CurriculumSets] WARNING: Too few finite centroids after filtering "
                        f"({len(self.tree_users)}). Falling back to random sets."
                    );
                    return;

            print("[CurriculumSets] Generating spatial index tree...");
            from scipy.spatial import cKDTree;
            self.tree = cKDTree(indexed_centroids);
            if len(invalid_users) > 0:
                print(
                    "[CurriculumSets] WARNING: Skipped "
                    f"{len(invalid_users)} users with non-finite centroids."
                );


    def get_random_sets_batch(self):
        X = [];
        Y = [];

        batch_users = random.sample(self.users, self.K);
        
        for i, batch_user in enumerate(batch_users):
            X.append(self.user_cache[batch_user]);
            Y.extend([i] * conf.N);

        return np.concatenate(X, axis=0), np.stack(Y);


    def get_sets_nearest(self, legitimate_user_idx, nearest_users):
        if self.tree is None:
            return self.get_random_sets_batch();

        X = [];
        Y = [];
        
        legitimate_user = self.users[legitimate_user_idx];
        if legitimate_user not in self.tree_user_set:
            return self.get_random_sets_batch();

        user_set_id = 0;

        # Add legitimate user samples
        X.append(self.user_cache[legitimate_user]);
        Y.extend([user_set_id] * conf.N);

        # Add nearest neighbours
        neighbours = max(1, min(nearest_users, len(self.tree_users)));
        distances, indices = self.tree.query(self.centroids[legitimate_user], k=neighbours);
        indices = np.atleast_1d(indices);

        impostors = set();
        for i in range(1, len(indices)):
            impostor_idx = int(indices[i]);
            if impostor_idx < 0 or impostor_idx >= len(self.tree_users):
                continue;
            impostor = self.tree_users[impostor_idx];
            if impostor == legitimate_user:
                continue;
            impostors.add(impostor);
            user_set_id += 1;

            X.append(self.user_cache[impostor]);
            Y.extend([user_set_id] * conf.N);

        # Fill remaining with random users
        while user_set_id < self.K - 1:
            impostor = random.choice(self.users);
            if impostor != legitimate_user and impostor not in impostors:
                impostors.add(impostor);
                user_set_id += 1;
                X.append(self.user_cache[impostor]);
                Y.extend([user_set_id] * conf.N);

        X = np.concatenate(X, axis=0);
        Y = np.stack(Y);
        return (X, Y);



    def __call__(self):
        while True:
            if self.epoch < self.delay or self.tree is None:
                yield self.get_random_sets_batch();
            else:
                legitimate_idx = random.randint(0, len(self.users) - 1);
                nearest_users = self.epoch // self.delay;
                
                max_nearest_users = min(self.K - 2, self.max_neighbours);
                if max_nearest_users < 1:
                    max_nearest_users = 1;
                if nearest_users > max_nearest_users:
                    nearest_users = max_nearest_users;

                yield self.get_sets_nearest(legitimate_idx, nearest_users + 1);




class GeneratorCallback(tf.keras.callbacks.Callback):
    def __init__(self, generator):
        self.generator = generator;

    def on_epoch_begin(self, epoch, logs=None):
        self.generator.on_epoch_begin(epoch, logs);

    def on_epoch_end(self, epoch, logs=None):
        self.generator.on_epoch_end(epoch, logs);


def get_generator(descriptor, x):
    print("    CurriculumSets");
    retval = CurriculumSetsGenerator(descriptor, x, conf.K, conf.CURRICULUM_DELAY, conf.CURRICULUM_MAX_NEIGHBOURS);
    retval.initialize();
    
    tc = GeneratorCallback(retval);
    return retval(), retval, tc;



