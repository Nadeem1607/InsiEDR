# Demo Runbook (Viva)

## 1) Start App on DGX
```bash
cd ~/repo
source /SASTRA-NEW-CLUSTER/apps/anaconda3/bin/activate
conda activate LABENV

# Prefer one low-contention GPU/MIG. If unstable, force CPU by setting CUDA_VISIBLE_DEVICES=""
export CUDA_VISIBLE_DEVICES=5
export TYPE2BRANCH_ENABLE_DATASET_SHAPE_SCAN=0
export TYPE2BRANCH_APP_MIN_KEYSTROKES=30
export TYPE2BRANCH_APP_MIN_TEMPLATES=3

streamlit run app.py --server.port 8502 --server.address 0.0.0.0
```

## 2) Tunnel from Laptop
Run this on laptop terminal (not DGX terminal):
```bash
ssh -L 8502:localhost:8502 P126033005@172.16.13.91
```
Open: `http://localhost:8502`

## 3) Live Enrollment Flow
1. Enter user ID.
2. Type prompted sentence.
3. Click `Copy JSON payload`.
4. Paste into JSON box.
5. Click `Save Enrollment Sample`.
6. Repeat until at least 3 templates/user.

## 4) Live Authentication Flow
1. Select enrolled user.
2. Type sentence and copy/paste payload.
3. Click `Authenticate`.
4. Show mean distance vs threshold and decision.

## 5) Fallbacks
- If app startup is slow: wait for spinner (first load can take minutes on shared DGX).
- If GPU is busy: `export CUDA_VISIBLE_DEVICES=""` and restart app.
- If threshold artifact missing: use sidebar override threshold for demo-only.
