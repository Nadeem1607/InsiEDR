# Top-K investigation queue evaluation

The model ranks hosts by max(error) × mean(error) × sqrt(sequence count). Top-K selects the first K ranked **review candidates**, irrespective of the binary alert threshold. It does not establish malicious intent or identify a confirmed insider. Positive/normal labels below are synthetic evaluation ground truth.

Primary results use the latest 15 eligible daily forecast errors for every host. Recall counts attack hosts within that same interval; it does not count every host attacked anywhere in the longer dataset. There are 216 eligible hosts per population.

## Equal 15-day ranking windows

### test: 9 attack hosts

| K | Attack hosts found | Normal hosts reviewed | Precision@K | Recall@K |
|---:|---:|---:|---:|---:|
| 5 | 3/9 | 2 | 60.0% | 33.3% |
| 10 | 5/9 | 5 | 50.0% | 55.6% |
| 15 | 6/9 | 9 | 40.0% | 66.7% |
| 20 | 6/9 | 14 | 30.0% | 66.7% |
| 30 | 6/9 | 24 | 20.0% | 66.7% |

### challenge: 13 attack hosts

| K | Attack hosts found | Normal hosts reviewed | Precision@K | Recall@K |
|---:|---:|---:|---:|---:|
| 5 | 4/13 | 1 | 80.0% | 30.8% |
| 10 | 8/13 | 2 | 80.0% | 61.5% |
| 15 | 9/13 | 6 | 60.0% | 69.2% |
| 20 | 11/13 | 9 | 55.0% | 84.6% |
| 30 | 11/13 | 19 | 36.7% | 84.6% |

### prospective_holdout: 18 attack hosts

| K | Attack hosts found | Normal hosts reviewed | Precision@K | Recall@K |
|---:|---:|---:|---:|---:|
| 5 | 4/18 | 1 | 80.0% | 22.2% |
| 10 | 8/18 | 2 | 80.0% | 44.4% |
| 15 | 13/18 | 2 | 86.7% | 72.2% |
| 20 | 16/18 | 4 | 80.0% | 88.9% |
| 30 | 17/18 | 13 | 56.7% | 94.4% |

## Supplementary full-period rankings

These intervals have different durations and different attack-host denominators. Do not compare these directly as equal-exposure evaluations. Test: 15 scored days; challenge: 23; prospective cohort: 53. The first seven standalone days lack forecasts.

### test: 9 attack hosts

| K | Attack hosts found | Normal hosts reviewed | Precision@K | Recall@K |
|---:|---:|---:|---:|---:|
| 5 | 3/9 | 2 | 60.0% | 33.3% |
| 10 | 5/9 | 5 | 50.0% | 55.6% |
| 15 | 6/9 | 9 | 40.0% | 66.7% |
| 20 | 6/9 | 14 | 30.0% | 66.7% |
| 30 | 6/9 | 24 | 20.0% | 66.7% |

### challenge: 23 attack hosts

| K | Attack hosts found | Normal hosts reviewed | Precision@K | Recall@K |
|---:|---:|---:|---:|---:|
| 5 | 4/23 | 1 | 80.0% | 17.4% |
| 10 | 8/23 | 2 | 80.0% | 34.8% |
| 15 | 12/23 | 3 | 80.0% | 52.2% |
| 20 | 14/23 | 6 | 70.0% | 60.9% |
| 30 | 18/23 | 12 | 60.0% | 78.3% |

### prospective_holdout: 18 attack hosts

| K | Attack hosts found | Normal hosts reviewed | Precision@K | Recall@K |
|---:|---:|---:|---:|---:|
| 5 | 4/18 | 1 | 80.0% | 22.2% |
| 10 | 9/18 | 1 | 90.0% | 50.0% |
| 15 | 13/18 | 2 | 86.7% | 72.2% |
| 20 | 18/18 | 2 | 90.0% | 100.0% |
| 30 | 18/18 | 12 | 60.0% | 100.0% |

## Interpretation

Recall@K answers how many attack hosts enter the investigation queue. Precision@K answers how many reviewed hosts truly have simulated attacks. Increasing K usually catches more attack hosts while increasing investigation workload. Neither metric is the model’s ordinary daily accuracy.

K values are reported as requested without selecting a preferred K on these test outcomes. Historical test/challenge data were previously inspected; the prospective cohort was generated after model freeze, but still shares synthetic mechanisms. Ground truth determines evaluation counts only, never the ranking order.
