import  numpy   as np;
import  random;

import  conf;



class RandomSetsGenerator:
    def __init__(self, descriptor, x, K):
        self.descriptor = descriptor;
        self.x = x;
        self.K = K;
    
        self.users = list(self.x.keys());
        if len(self.users) < self.K:
            raise ValueError(
                f"RandomSetsGenerator requires at least K users (K={self.K}, users={len(self.users)}). "
                "Lower conf.K or ingest more users."
            );

        # Pre-cache N samples per user (oversample if needed)
        self.user_samples = {};
        for user_id, samples in self.x.items():
            sample_list = [np.asarray(s, dtype=np.float32) for s in samples.values()];
            self.user_samples[user_id] = np.stack(sample_list, axis=0);


    def _draw_user_samples(self, user_id):
        pool = self.user_samples[user_id];
        total = pool.shape[0];
        replace = total < conf.N;
        picked = np.random.choice(total, size=conf.N, replace=replace);
        return pool[picked];


    def get_random_sets_batch(self):
        X = [];
        Y = [];

        batch_users = random.sample(self.users, self.K);
        
        for i, batch_user in enumerate(batch_users):
            X.append(self._draw_user_samples(batch_user));
            Y.extend([i] * conf.N);

        return np.concatenate(X, axis=0), np.stack(Y);


    def __call__(self):
        while True:
            yield self.get_random_sets_batch();




def get_generator(descriptor, x):
    print("    RandomSets");
    retval = RandomSetsGenerator(descriptor, x, conf.K);
    return retval(), retval, None;



