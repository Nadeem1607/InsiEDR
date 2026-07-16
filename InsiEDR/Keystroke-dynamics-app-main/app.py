import hashlib
import json
import os
import uuid
from datetime import datetime
from typing import List, Optional, Tuple

import numpy as np
import streamlit as st
from streamlit.components.v1 import html as st_html

import detect_llm_paste


st.set_page_config(
    page_title="Type2Branch | Deep Biometrics",
    layout="wide",
    page_icon="🔐",
)

st.markdown("""
<style>
    /* Ultra-Premium Glassmorphic Cybersecurity Theme */
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }
    
    /* Subtle animated dark gradient background for the whole app */
    .stApp {
        background: radial-gradient(circle at top right, #0f172a 0%, #020617 100%);
        background-attachment: fixed;
    }

    /* Hide Deploy button and hamburger menu for cleaner demo */
    .stDeployButton {display:none !important;}
    #MainMenu {visibility: hidden !important;}
    header {visibility: hidden !important;}
    footer {visibility: hidden !important;}

    /* Premium Typography */
    h1 {
        font-weight: 700 !important;
        background: linear-gradient(135deg, #00f0ff 0%, #3b82f6 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-shadow: 0px 4px 15px rgba(0, 240, 255, 0.2);
    }
    h2, h3 {
        font-weight: 600 !important;
        color: #f8fafc !important;
        letter-spacing: 0.5px;
    }

    /* Modernize Streamlit tabs - Glassmorphic pills */
    .stTabs [data-baseweb="tab-list"] {
        gap: 15px;
        background-color: rgba(15, 23, 42, 0.4);
        padding: 5px;
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
    }
    .stTabs [data-baseweb="tab"] {
        height: 45px;
        border-radius: 8px;
        background-color: transparent;
        padding: 0 24px;
        color: #94a3b8;
        font-weight: 500;
        border: none !important;
        transition: all 0.3s ease;
    }
    .stTabs [data-baseweb="tab"]:hover {
        color: #e2e8f0;
        background-color: rgba(255, 255, 255, 0.03);
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, rgba(0, 240, 255, 0.1) 0%, rgba(59, 130, 246, 0.1) 100%) !important;
        color: #00f0ff !important;
        box-shadow: 0 0 15px rgba(0, 240, 255, 0.15) !important;
        border: 1px solid rgba(0, 240, 255, 0.3) !important;
    }
    .stTabs [data-baseweb="tab-highlight"] {
        display: none; /* Hide the default bottom border line */
    }
    
    /* Make metrics pop with glass cards */
    [data-testid="stMetricValue"] {
        font-size: 2.5rem;
        font-weight: 700;
        color: #00f0ff;
        text-shadow: 0 0 10px rgba(0, 240, 255, 0.3);
    }
    [data-testid="stMetricLabel"] {
        font-weight: 500;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-size: 0.85rem;
    }
    [data-testid="metric-container"] {
        background: rgba(15, 23, 42, 0.6);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 16px;
        padding: 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    [data-testid="metric-container"]:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(0, 240, 255, 0.15);
        border: 1px solid rgba(0, 240, 255, 0.2);
    }
    
    /* Subtle glow on main containers */
    .block-container {
        padding-top: 3rem;
        max-width: 1200px;
    }
    
    /* Text input styling */
    .stTextInput input {
        border-radius: 8px !important;
        border: 1px solid rgba(148, 163, 184, 0.2) !important;
        background: rgba(15, 23, 42, 0.8) !important;
        color: #f8fafc !important;
    }
    .stTextInput input:focus {
        border-color: #00f0ff !important;
        box-shadow: 0 0 0 2px rgba(0, 240, 255, 0.2) !important;
    }

    /* JetBrains Mono for code/payload areas */
    code, pre, .ksr-mono {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: rgba(5, 10, 30, 0.9) !important;
        border-right: 1px solid rgba(0, 240, 255, 0.08) !important;
    }
    [data-testid="stSidebar"] .stMarkdown p,
    [data-testid="stSidebar"] label {
        color: #94a3b8 !important;
        font-size: 0.85rem !important;
    }

    /* Primary button glow */
    .stButton button[kind="primary"],
    button[data-testid="stFormSubmitButton"] {
        background: linear-gradient(135deg, #0ea5e9 0%, #00f0ff 100%) !important;
        color: #020617 !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 10px !important;
        box-shadow: 0 0 20px rgba(0, 240, 255, 0.25) !important;
        transition: all 0.25s ease !important;
        letter-spacing: 0.5px !important;
    }
    .stButton button[kind="primary"]:hover,
    button[data-testid="stFormSubmitButton"]:hover {
        box-shadow: 0 0 35px rgba(0, 240, 255, 0.45) !important;
        transform: translateY(-1px) !important;
    }

    /* Selectbox */
    [data-testid="stSelectbox"] > div > div {
        background: rgba(15, 23, 42, 0.8) !important;
        border: 1px solid rgba(148, 163, 184, 0.2) !important;
        border-radius: 8px !important;
        color: #f8fafc !important;
    }

    /* Expander */
    [data-testid="stExpander"] {
        background: rgba(15, 23, 42, 0.4) !important;
        border: 1px solid rgba(255, 255, 255, 0.05) !important;
        border-radius: 10px !important;
    }

    /* Divider */
    hr {
        border-color: rgba(255, 255, 255, 0.06) !important;
    }

    /* Alert / warning boxes */
    .stAlert {
        border-radius: 10px !important;
    }

    /* Success banner */
    [data-testid="stSuccess"] {
        background: rgba(16, 185, 129, 0.1) !important;
        border: 1px solid rgba(16, 185, 129, 0.3) !important;
        border-radius: 12px !important;
    }

    /* Error banner */
    [data-testid="stError"] {
        background: rgba(239, 68, 68, 0.1) !important;
        border: 1px solid rgba(239, 68, 68, 0.3) !important;
        border-radius: 12px !important;
    }

    /* Table styling for leaderboard */
    [data-testid="stDataFrame"] {
        border-radius: 12px !important;
        overflow: hidden !important;
    }
</style>
""", unsafe_allow_html=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENROLLMENTS_PATH = os.path.join(BASE_DIR, "artifacts", "enrollments.json")
CHECKPOINT_PATH  = os.path.join(BASE_DIR, "model", "checkpoint.weights.h5")
os.environ.setdefault("TF_FORCE_GPU_ALLOW_GROWTH", "true")

# ─── Production Config ──────────────────────────────────────────────────────
MIN_ENROLLMENT_TEMPLATES = 15         # Minimum templates before auth is enabled
ROLLING_GALLERY_MAX      = 20         # Max stored embeddings per user
PERSONAL_THRESHOLD_PERCENTILE = 90    # p90 of genuine distances as base threshold
THRESHOLD_SAFETY_MARGIN  = 1.00       # × multiplier on top of p90 (0% buffer)
MAX_CONSEC_FAILS_STEPUP  = 2          # Soft anomalies before step-up challenge
MAX_CONSEC_FAILS_LOCKOUT = 4          # Hard anomalies before lockout

# Challenge phrase pool — rotated per session (anti-replay)
CHALLENGE_PHRASES = [
    "The quick brown fox jumps over the lazy dog. Cybersecurity relies on evaluating behavioral metrics directly.",
    "Authentication systems must validate identity through multiple layers of behavioral analysis.",
    "Keystroke dynamics capture the unique rhythm and timing patterns of an individual typist.",
    "Biometric security combines something you know with something you are for stronger protection.",
    "Machine learning models trained on temporal sequences reveal deep behavioral fingerprints.",
    "Continuous authentication monitors user identity throughout an entire working session silently.",
    "Neural networks process timing data to distinguish genuine users from potential impostors.",
    "The fusion of recurrent and convolutional pathways enables robust behavioural modelling.",
    "Security systems must balance false acceptance rates against user experience and friction.",
    "Dynamic time warping and deep metric learning form the backbone of modern keystroke systems.",
]


# â”€â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def load_threshold_artifact():
    env_thr = os.environ.get("TYPE2BRANCH_THRESHOLD_ARTIFACT", "").strip()
    candidates = [
        (os.path.join(BASE_DIR, "docs", "Final_EER_Report.json"),                   "threshold_tuned_on_xv"),
        (os.path.join(BASE_DIR, "results_hardened", "threshold_artifact.json"),   "threshold"),
        (os.path.join(BASE_DIR, "results_hardened", "hardened_metrics.json"),      "threshold_tuned_on_xv"),
        (
            os.path.join(BASE_DIR, "results_continuous", "continuous_metrics.json"),
            ("threshold_tuning_xv", "threshold"),
        ),
    ]
    if env_thr:
        candidates.insert(0, (env_thr, "threshold_tuned_on_xv"))
        candidates.insert(0, (env_thr, "threshold"))

    for path, key in candidates:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                obj = json.load(f)
        except Exception:
            continue

        if isinstance(key, tuple):
            cur, ok = obj, True
            for k in key:
                if not isinstance(cur, dict) or k not in cur:
                    ok = False
                    break
                cur = cur[k]
            if not ok:
                continue
            threshold = float(cur)
        else:
            if key not in obj:
                continue
            threshold = float(obj[key])

        return {
            "path":             path,
            "threshold":        threshold,
            "sequence_length":  int(obj.get("sequence_length",  100)),
            "input_features":   int(obj.get("input_features",    5)),
            "checkpoint":       obj.get("checkpoint", CHECKPOINT_PATH),
            "dataset":          obj.get("dataset"),
        }
    return None


def short_sha256(path):
    if not os.path.exists(path):
        return "missing"
    stt = os.stat(path)
    payload = f"{path}|{int(stt.st_mtime)}|{stt.st_size}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:12]


def resolve_checkpoint_path(threshold_info):
    env_cp = os.environ.get("TYPE2BRANCH_CHECKPOINT_PATH", "").strip()
    if env_cp:
        return env_cp
    if threshold_info and threshold_info.get("checkpoint"):
        cp = str(threshold_info["checkpoint"])
        return cp if os.path.isabs(cp) else os.path.join(BASE_DIR, cp)
    return CHECKPOINT_PATH


def build_runtime_candidates(threshold_info) -> List[Tuple[int, int, str]]:
    candidates: List[Tuple[int, int, str]] = []
    seen: set = set()

    def add(seq_len, input_features, src):
        key = (int(seq_len), int(input_features))
        if key not in seen:
            seen.add(key)
            candidates.append((int(seq_len), int(input_features), src))

    if threshold_info:
        add(threshold_info["sequence_length"], threshold_info["input_features"],
            f"threshold_artifact:{threshold_info['path']}")

    env_seq  = os.environ.get("TYPE2BRANCH_SEQUENCE_LENGTH", "").strip()
    env_feat = os.environ.get("TYPE2BRANCH_INPUT_FEATURES",  "").strip()
    if env_seq and env_feat:
        try:
            add(int(env_seq), int(env_feat), "env:SEQ/FEAT")
        except ValueError:
            pass

    # Dataset shape scan is expensive on large object npy splits.
    # Keep it opt-in for demo responsiveness.
    if os.environ.get("TYPE2BRANCH_ENABLE_DATASET_SHAPE_SCAN", "0") == "1":
        for ds in ["aalto_desktop_merged", "aalto_desktop"]:
            result = _infer_shape_from_dataset(ds)
            if result:
                add(result[0], result[1], f"dataset:{ds}")
                break

    add(100, 5, "fallback_default")
    add(150, 5, "legacy_fallback")
    return candidates


@st.cache_data(show_spinner=False)
def _infer_shape_from_dataset(dataset_name: str):
    base = os.path.join(BASE_DIR, "datasets", dataset_name, "npy")
    for split in ("xt.npy", "xv.npy", "xe.npy"):
        sp = os.path.join(base, split)
        if not os.path.exists(sp):
            continue
        try:
            part = np.load(sp, allow_pickle=True).item()
            if not isinstance(part, dict) or not part:
                continue
            first_user    = next(iter(part.keys()))
            first_samples = part[first_user]
            if not isinstance(first_samples, dict) or not first_samples:
                continue
            first_sample  = next(iter(first_samples.values()))
            if isinstance(first_sample, np.ndarray) and first_sample.ndim == 2:
                return int(first_sample.shape[0]), int(first_sample.shape[1])
        except Exception:
            continue
    return None


@st.cache_resource
def load_model_cached(seq_len: int, input_features: int,
                      checkpoint_path: str, checkpoint_fingerprint: str = ""):
    descriptor = {"SEQUENCE_LENGTH": int(seq_len), "INPUT_FEATURES": int(input_features)}
    try:
        import tensorflow as tf
        for gpu in tf.config.list_physical_devices("GPU"):
            tf.config.experimental.set_memory_growth(gpu, True)
    except Exception as exc:
        return None, descriptor, False, f"TensorFlow runtime unavailable: {exc}"

    try:
        import model as model_module
        descriptor = model_module.get_model_Type2Branch(descriptor, build_optimizer=False)
        m = descriptor["model"]
    except Exception as exc:
        return None, descriptor, False, f"Model construction failed: {exc}"

    has_weights = os.path.exists(checkpoint_path)
    load_error: Optional[str] = None
    if has_weights:
        try:
            m.load_weights(checkpoint_path)
        except Exception as exc:
            has_weights = False
            load_error  = str(exc)
    return m, descriptor, has_weights, load_error


def load_best_model(candidates: List[Tuple[int, int, str]],
                    checkpoint_path: str, checkpoint_fingerprint: str):
    if not candidates:
        candidates = [(100, 5, "fallback_default")]

    # If checkpoint file doesn't exist, use first candidate and skip iteration.
    if not os.path.exists(checkpoint_path):
        seq_len, input_features, source = candidates[0]
        m, descriptor, has_weights, load_error = load_model_cached(
            seq_len, input_features, checkpoint_path, checkpoint_fingerprint
        )
        return m, descriptor, has_weights, load_error, source

    first = None
    last_error: Optional[str] = None
    for seq_len, input_features, source in candidates:
        m, descriptor, has_weights, load_error = load_model_cached(
            seq_len, input_features, checkpoint_path, checkpoint_fingerprint
        )
        if has_weights:
            return m, descriptor, has_weights, load_error, source
        if load_error:
            last_error = load_error
        if first is None:
            first = (m, descriptor, has_weights, load_error, source)

    # All candidates failed - return first attempt so UI can show the error.
    if first is None:
        m, descriptor, has_weights, load_error = load_model_cached(
            100, 5, checkpoint_path, checkpoint_fingerprint
        )
        return m, descriptor, has_weights, load_error, "fallback_default"
    if last_error is not None:
        return first[0], first[1], first[2], last_error, first[4]
    return first


def load_enrollments(seq_len: int, input_features: int):
    if not os.path.exists(ENROLLMENTS_PATH):
        return {}, []
    try:
        with open(ENROLLMENTS_PATH, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return {}, ["Could not parse enrollments file; starting empty."]

    out: dict = {}
    warnings: List[str] = []
    for user_id, entry in payload.get("users", {}).items():
        e_seq  = int(entry.get("sequence_length", seq_len))
        e_feat = int(entry.get("input_features",  input_features))
        if e_seq != seq_len or e_feat != input_features:
            warnings.append(
                f"Skipped '{user_id}': shape ({e_seq},{e_feat}) != current ({seq_len},{input_features})"
            )
            continue
        embs = []
        for raw in entry.get("embeddings", []):
            arr = np.array(raw, dtype=np.float32)
            if arr.ndim == 1 and arr.size > 0:
                embs.append(arr)
        if embs:
            out[user_id] = embs
    return out, warnings


def save_enrollments(enrollments: dict, seq_len: int, input_features: int,
                     checkpoint_hash: str, threshold_source: str):
    os.makedirs(os.path.dirname(ENROLLMENTS_PATH), exist_ok=True)
    payload = {
        "version":               1,
        "updated_at":            datetime.utcnow().isoformat() + "Z",
        "sequence_length":       int(seq_len),
        "input_features":        int(input_features),
        "checkpoint_sha256_short": checkpoint_hash,
        "threshold_source":      threshold_source,
        "users": {
            uid: {
                "sequence_length":  int(seq_len),
                "input_features":   int(input_features),
                "num_templates":    len(embs),
                "embeddings":       [e.astype(np.float32).tolist() for e in embs],
            }
            for uid, embs in enrollments.items()
        },
    }
    tmp = ENROLLMENTS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.replace(tmp, ENROLLMENTS_PATH)


def process_raw_events(raw_json_string: str, seq_length: int,
                       input_features: int) -> Tuple[Optional[np.ndarray], str]:
    """Parse JSON keystroke array -> (seq_length, input_features) float32, and decoded string."""
    decoded_text = ""
    try:
        events = json.loads(raw_json_string)
    except Exception as exc:
        st.error(f"Could not parse keystroke JSON: {exc}")
        return None, ""

    if not isinstance(events, list):
        st.error("Payload must be a JSON array.")
        return None, ""
    min_keystrokes = int(os.environ.get("TYPE2BRANCH_APP_MIN_KEYSTROKES", "200"))
    if len(events) < min_keystrokes:
        st.error(
            f"Only {len(events)} keystrokes captured; need at least {min_keystrokes}. "
            "Type the full sentence before copying the payload."
        )
        return None, ""

    # Decode text for secret word check BEFORE truncation
    for ev in events:
        if isinstance(ev, list) and len(ev) > 0 and ev[0] > 0:
            char_code = int(round(ev[0] * 255.0))
            if 32 <= char_code <= 126: # Only printable ASCII
                decoded_text += chr(char_code)

    # Truncate / zero-pad to seq_length for the AI model
    events = list(events[:seq_length])
    if len(events) < seq_length:
        events.extend([[0, 0, 0]] * (seq_length - len(events)))

    arr = np.array(events, dtype=np.float32)
    if arr.ndim != 2 or arr.shape[1] < 3:
        st.error("Invalid payload: expected rows of [keycode_norm, hold_s, flight_s].")
        return None, ""

    # Build standardised features: keycode_norm | hold_s | flight_s | centered_hold | centered_flight
    mean_ht = float(np.mean(arr[:, 1]))
    mean_ft = float(np.mean(arr[:, 2]))
    sht     = arr[:, 1] - mean_ht
    sft     = arr[:, 2] - mean_ft
    final   = np.column_stack((arr[:, :3], sht, sft)).astype(np.float32)

    if input_features < 5:
        final = final[:, :input_features]
    elif input_features > 5:
        pad   = np.zeros((seq_length, input_features - 5), dtype=np.float32)
        final = np.concatenate([final, pad], axis=1)
    return final, decoded_text


def process_continuous_events(raw_json_string: str, seq_length: int,
                              input_features: int, stride: int = 10) -> Tuple[Optional[List[np.ndarray]], str]:
    """Parse JSON keystroke array -> list of (seq_length, input_features) float32 windows, and decoded string."""
    decoded_text = ""
    try:
        events = json.loads(raw_json_string)
    except Exception as exc:
        st.error(f"Could not parse keystroke JSON: {exc}")
        return None, ""

    if not isinstance(events, list):
        st.error("Payload must be a JSON array.")
        return None, ""
    
    min_keystrokes = int(os.environ.get("TYPE2BRANCH_APP_MIN_KEYSTROKES", "200"))
    if len(events) < min_keystrokes:
        st.error(
            f"Only {len(events)} keystrokes captured; need at least {min_keystrokes}. "
            "Type the full sentence before copying the payload."
        )
        return None, ""

    # Decode text for secret word check
    for ev in events:
        if isinstance(ev, list) and len(ev) > 0 and ev[0] > 0:
            char_code = int(round(ev[0] * 255.0))
            if 32 <= char_code <= 126: # Only printable ASCII
                decoded_text += chr(char_code)

    arr = np.array(events, dtype=np.float32)
    if arr.ndim != 2 or arr.shape[1] < 3:
        st.error("Invalid payload: expected rows of [keycode_norm, hold_s, flight_s].")
        return None, ""
        
    windows = []
    if len(arr) <= seq_length:
        starts = [0]
    else:
        starts = list(range(0, len(arr) - seq_length + 1, stride))
        if not starts or starts[-1] + seq_length < len(arr):
            starts.append(len(arr) - seq_length)
            
    starts = sorted(list(set(starts)))
    
    for start in starts:
        window_events = arr[start:start+seq_length]
        if len(window_events) < seq_length:
            pad_len = seq_length - len(window_events)
            pad = np.zeros((pad_len, arr.shape[1]), dtype=np.float32)
            window_events = np.vstack([window_events, pad])
            
        mean_ht = float(np.mean(window_events[:, 1]))
        mean_ft = float(np.mean(window_events[:, 2]))
        sht     = window_events[:, 1] - mean_ht
        sft     = window_events[:, 2] - mean_ft
        final   = np.column_stack((window_events[:, :3], sht, sft)).astype(np.float32)

        if input_features < 5:
            final = final[:, :input_features]
        elif input_features > 5:
            pad   = np.zeros((seq_length, input_features - 5), dtype=np.float32)
            final = np.concatenate([final, pad], axis=1)
            
        windows.append(final)

    return windows, decoded_text


def gallery_distance(gallery_embeddings: list, query_embedding: np.ndarray):
    gallery   = np.stack(gallery_embeddings, axis=0)
    distances = np.linalg.norm(gallery - query_embedding, axis=1)
    return float(np.mean(distances)), float(np.min(distances))


# ─── Production: Per-User Threshold Engine ──────────────────────────────────

def compute_personal_threshold(embeddings: list) -> Optional[float]:
    """Compute a tight per-user threshold from the genuine gallery.
    Uses the p90 of all pairwise L2 distances * THRESHOLD_SAFETY_MARGIN.
    Returns None if not enough templates.
    """
    import itertools
    if len(embeddings) < 2:
        return None
    dists = [float(np.linalg.norm(a - b))
             for a, b in itertools.combinations(embeddings, 2)]
    p_thr = float(np.percentile(dists, PERSONAL_THRESHOLD_PERCENTILE))
    return p_thr * THRESHOLD_SAFETY_MARGIN


def compute_enrollment_quality(embeddings: list) -> dict:
    """Return quality stats for the enrollment gallery."""
    import itertools
    if len(embeddings) < 2:
        return {"score": 0.0, "n": len(embeddings),
                "intra_mean": None, "intra_std": None, "threshold": None}
    dists = [float(np.linalg.norm(a - b))
             for a, b in itertools.combinations(embeddings, 2)]
    mu  = float(np.mean(dists))
    std = float(np.std(dists))
    # EQS: 0→1, high = consistent (low relative std)
    eqs = max(0.0, 1.0 - (std / (mu + 1e-6)))
    thr = compute_personal_threshold(embeddings)
    return {"score": round(eqs, 3), "n": len(embeddings),
            "intra_mean": round(mu, 4), "intra_std": round(std, 4),
            "threshold": round(thr, 4) if thr else None}


def is_enrollment_outlier(new_emb: np.ndarray, existing_embs: list,
                          sigma: float = 2.5) -> tuple:
    """Return (is_outlier, reason) for a new enrollment sample."""
    if len(existing_embs) < 2:
        return False, ""
    q = compute_enrollment_quality(existing_embs)
    mu  = q["intra_mean"]
    std = q["intra_std"]
    if mu is None or std is None:
        return False, ""
    centroid = np.mean(np.stack(existing_embs), axis=0)
    dist_to_centroid = float(np.linalg.norm(new_emb - centroid))
    # If new sample is more than sigma*std away from centroid, flag it
    cutoff = mu + sigma * (std + 1e-6)
    if dist_to_centroid > cutoff:
        return True, (f"Sample distance {dist_to_centroid:.2f} from gallery centre "
                      f"exceeds cutoff {cutoff:.2f} (μ={mu:.2f}, σ={std:.2f}). "
                      "Retake more naturally.")
    return False, ""


def check_typing_plausibility(raw_events: list) -> tuple:
    """Check for superhuman / bot / replay patterns.
    Returns (is_suspicious, reason).
    """
    if len(raw_events) < 5:
        return False, ""
    holds  = [ev[1] for ev in raw_events if isinstance(ev, list) and len(ev) > 1]
    flights = [ev[2] for ev in raw_events if isinstance(ev, list) and len(ev) > 2]
    if not holds:
        return False, ""
    # 1. Superhuman consistency: hold time variance < 0.5ms
    h_std = float(np.std(holds))
    if h_std < 0.0005:
        return True, f"Hold-time std {h_std*1000:.2f}ms is impossibly consistent (bot suspected)"
    # 2. Superhuman speed: mean hold < 20ms
    h_mean = float(np.mean(holds))
    if h_mean < 0.020:
        return True, f"Mean hold {h_mean*1000:.0f}ms is superhuman (< 20ms)"
    # 3. All identical hold times (replayed vector)
    unique_holds = len(set(round(h, 4) for h in holds))
    if unique_holds < max(3, len(holds) // 10):
        return True, f"Only {unique_holds} unique hold times — possible replay attack"
    # 4. Flight time all zero (paste / instant input)
    if flights:
        f_mean = float(np.mean([abs(f) for f in flights]))
        if f_mean < 0.001:
            return True, "All flight times near-zero — paste or replay detected"
    return False, ""


# ─── Production: Rolling Gallery Update ─────────────────────────────────────

def update_rolling_gallery(existing_embs: list, new_emb: np.ndarray) -> list:
    """Append new_emb and enforce rolling window of ROLLING_GALLERY_MAX."""
    updated = existing_embs + [new_emb]
    if len(updated) > ROLLING_GALLERY_MAX:
        updated = updated[-ROLLING_GALLERY_MAX:]
    return updated


# â”€â”€â”€ Keystroke recorder HTML component â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#
# Architecture:
#   â€¢ An HTML iframe records keydown/keyup timestamps internally.
#   â€¢ A "Copy JSON payload" button writes the array to the clipboard.
#   â€¢ The user pastes into a Streamlit text_area below with a STABLE key.
#   â€¢ session_state stores the payload so it survives button-click reruns.
#   â€¢ After a successful save/auth, the caller clears the session_state key.
#
# Key stability rule (fixes DuplicateWidgetID + value-loss bugs):
#   We use a fixed key derived from `mode` only â€” never from uuid or id().

# ─── XAI: Extract raw timing stats from keystroke payload ────────────────────

def extract_timing_stats(raw_events: list) -> dict:
    """Return mean/std of hold & flight times (in ms) from raw event list."""
    holds   = [ev[1] * 1000.0 for ev in raw_events if isinstance(ev, list) and len(ev) > 1]
    flights = [ev[2] * 1000.0 for ev in raw_events if isinstance(ev, list) and len(ev) > 2]
    if not holds:
        return {}
    result = {
        "hold_mean":   float(np.mean(holds)),
        "hold_std":    float(np.std(holds)),
        "hold_p25":    float(np.percentile(holds, 25)),
        "hold_p75":    float(np.percentile(holds, 75)),
        "flight_mean": float(np.mean([abs(x) for x in flights])) if flights else 0.0,
        "flight_std":  float(np.std([abs(x) for x in flights]))  if flights else 0.0,
        "n_keys":      len(holds),
    }
    return result


def render_xai_comparison(query_stats: dict, baseline_stats: dict, label: str = "Query") -> None:
    """Render a bar chart comparing query timing vs genuine baseline."""
    if not query_stats or not baseline_stats:
        return
    try:
        import plotly.graph_objects as go
    except ImportError:
        st.info("Install plotly for XAI charts: pip install plotly")
        return

    metrics = ["Hold Mean (ms)", "Hold Std (ms)", "Flight Mean (ms)", "Flight Std (ms)"]
    query_vals = [
        query_stats.get("hold_mean",   0),
        query_stats.get("hold_std",    0),
        query_stats.get("flight_mean", 0),
        query_stats.get("flight_std",  0),
    ]
    baseline_vals = [
        baseline_stats.get("hold_mean",   0),
        baseline_stats.get("hold_std",    0),
        baseline_stats.get("flight_mean", 0),
        baseline_stats.get("flight_std",  0),
    ]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        name="Genuine Baseline",
        x=metrics, y=baseline_vals,
        marker_color="rgba(0,240,255,0.7)",
        marker_line_color="#00f0ff", marker_line_width=1.5,
    ))
    fig.add_trace(go.Bar(
        name=label,
        x=metrics, y=query_vals,
        marker_color="rgba(239,68,68,0.6)" if label != "Genuine User" else "rgba(16,185,129,0.6)",
        marker_line_color="#ef4444" if label != "Genuine User" else "#10b981",
        marker_line_width=1.5,
    ))
    fig.update_layout(
        barmode="group",
        title=dict(text="⚡ Keystroke Timing Signature Comparison", font=dict(color="#f8fafc", size=14)),
        paper_bgcolor="rgba(15,23,42,0.0)",
        plot_bgcolor="rgba(15,23,42,0.4)",
        font=dict(color="#94a3b8", size=11),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#e2e8f0")),
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)", title="milliseconds"),
        margin=dict(l=20, r=20, t=45, b=20),
        height=320,
    )
    st.plotly_chart(fig, use_container_width=True)


# ─── Feature 3: PCA Embed Space Visualization ────────────────────────────────

def render_embed_scatter(gallery_embs: list, query_emb: np.ndarray,
                         label: str = "Query", granted: bool = False) -> None:
    """Render 2D PCA scatter: gallery = green cluster, query = colored dot."""
    if len(gallery_embs) < 2:
        return
    try:
        import plotly.graph_objects as go
    except ImportError:
        st.info("Install plotly: pip install plotly")
        return

    # Stack gallery + query
    all_embs = np.stack(gallery_embs + [query_emb], axis=0)  # (N+1, D)
    # Manual PCA (2 components) — no sklearn needed
    mu  = all_embs.mean(axis=0)
    X   = all_embs - mu
    cov = np.cov(X.T)
    if cov.ndim < 2:
        return
    try:
        vals, vecs = np.linalg.eigh(cov)
    except Exception:
        return
    # Take top 2 eigenvectors (largest eigenvalues)
    idx = np.argsort(vals)[::-1]
    pc  = vecs[:, idx[:2]]
    coords = X @ pc  # (N+1, 2)

    gallery_pts = coords[:len(gallery_embs)]
    query_pt    = coords[len(gallery_embs)]

    fig = go.Figure()
    # Gallery cluster
    fig.add_trace(go.Scatter(
        x=gallery_pts[:, 0], y=gallery_pts[:, 1],
        mode="markers",
        name="Genuine Gallery",
        marker=dict(color="rgba(0,240,255,0.8)", size=10,
                    line=dict(color="#00f0ff", width=1.5),
                    symbol="circle"),
    ))
    # Centroid
    cx, cy = float(gallery_pts[:, 0].mean()), float(gallery_pts[:, 1].mean())
    fig.add_trace(go.Scatter(
        x=[cx], y=[cy], mode="markers", name="Centroid",
        marker=dict(color="#00f0ff", size=16, symbol="star",
                    line=dict(color="#ffffff", width=1)),
    ))
    # Query point
    q_color = "#10b981" if granted else "#ef4444"
    q_sym   = "circle-dot" if granted else "x"
    fig.add_trace(go.Scatter(
        x=[query_pt[0]], y=[query_pt[1]], mode="markers",
        name=label,
        marker=dict(color=q_color, size=16, symbol=q_sym,
                    line=dict(color="white", width=2)),
    ))
    fig.update_layout(
        title=dict(text="🧠 Embedding Space — PCA Projection", font=dict(color="#f8fafc", size=14)),
        paper_bgcolor="rgba(15,23,42,0.0)",
        plot_bgcolor="rgba(15,23,42,0.4)",
        font=dict(color="#94a3b8", size=11),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#e2e8f0")),
        xaxis=dict(title="PC-1", gridcolor="rgba(255,255,255,0.05)", zeroline=False),
        yaxis=dict(title="PC-2", gridcolor="rgba(255,255,255,0.05)", zeroline=False),
        margin=dict(l=20, r=20, t=45, b=20),
        height=370,
    )
    st.plotly_chart(fig, use_container_width=True)


# ─── Feature 5: Leaderboard helpers ─────────────────────────────────────────

def leaderboard_record(attacker_name: str, min_dist: float, verdict: str,
                       query_stats: dict) -> dict:
    return {
        "name":      attacker_name,
        "min_dist":  round(min_dist, 4),
        "verdict":   verdict,
        "hold_mean": round(query_stats.get("hold_mean", 0), 1),
        "flight_mean": round(query_stats.get("flight_mean", 0), 1),
        "ts":        datetime.now().strftime("%H:%M:%S"),
    }



# ─── XAI: Extract raw timing stats from keystroke payload ────────────────────

def extract_timing_stats(raw_events: list) -> dict:
    """Return mean/std of hold & flight times (in ms) from raw event list."""
    holds   = [ev[1] * 1000.0 for ev in raw_events if isinstance(ev, list) and len(ev) > 1]
    flights = [ev[2] * 1000.0 for ev in raw_events if isinstance(ev, list) and len(ev) > 2]
    if not holds:
        return {}
    result = {
        "hold_mean":   float(np.mean(holds)),
        "hold_std":    float(np.std(holds)),
        "hold_p25":    float(np.percentile(holds, 25)),
        "hold_p75":    float(np.percentile(holds, 75)),
        "flight_mean": float(np.mean([abs(x) for x in flights])) if flights else 0.0,
        "flight_std":  float(np.std([abs(x) for x in flights]))  if flights else 0.0,
        "n_keys":      len(holds),
    }
    return result

def render_xai_comparison(query_stats: dict, baseline_stats: dict, label: str = "Query") -> None:
    """Render a bar chart comparing query timing vs genuine baseline."""
    if not query_stats or not baseline_stats:
        return
    try:
        import plotly.graph_objects as go
    except ImportError:
        st.info("Install plotly for XAI charts: pip install plotly")
        return

    metrics = ["Hold Mean (ms)", "Hold Std (ms)", "Flight Mean (ms)", "Flight Std (ms)"]
    query_vals = [
        query_stats.get("hold_mean",   0),
        query_stats.get("hold_std",    0),
        query_stats.get("flight_mean", 0),
        query_stats.get("flight_std",  0),
    ]
    baseline_vals = [
        baseline_stats.get("hold_mean",   0),
        baseline_stats.get("hold_std",    0),
        baseline_stats.get("flight_mean", 0),
        baseline_stats.get("flight_std",  0),
    ]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        name="Genuine Baseline",
        x=metrics, y=baseline_vals,
        marker_color="rgba(0,240,255,0.7)",
        marker_line_color="#00f0ff", marker_line_width=1.5,
    ))
    fig.add_trace(go.Bar(
        name=label,
        x=metrics, y=query_vals,
        marker_color="rgba(239,68,68,0.6)" if label != "Genuine User" else "rgba(16,185,129,0.6)",
        marker_line_color="#ef4444" if label != "Genuine User" else "#10b981",
        marker_line_width=1.5,
    ))
    fig.update_layout(
        barmode="group",
        title=dict(text="⚡ Keystroke Timing Signature Comparison", font=dict(color="#f8fafc", size=14)),
        paper_bgcolor="rgba(15,23,42,0.0)",
        plot_bgcolor="rgba(15,23,42,0.4)",
        font=dict(color="#94a3b8", size=11),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#e2e8f0")),
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)", title="milliseconds"),
        margin=dict(l=20, r=20, t=45, b=20),
        height=320,
    )
    st.plotly_chart(fig, use_container_width=True)

def render_embed_scatter(gallery_embs: list, query_emb: np.ndarray,
                         label: str = "Query", granted: bool = False) -> None:
    """Render 2D PCA scatter: gallery = green cluster, query = colored dot."""
    if len(gallery_embs) < 2:
        return
    try:
        import plotly.graph_objects as go
    except ImportError:
        st.info("Install plotly: pip install plotly")
        return

    import numpy as np
    all_embs = np.stack(gallery_embs + [query_emb], axis=0)
    mu  = all_embs.mean(axis=0)
    X   = all_embs - mu
    cov = np.cov(X.T)
    if cov.ndim < 2:
        return
    try:
        vals, vecs = np.linalg.eigh(cov)
    except Exception:
        return
    idx = np.argsort(vals)[::-1]
    pc  = vecs[:, idx[:2]]
    coords = X @ pc

    gallery_pts = coords[:len(gallery_embs)]
    query_pt    = coords[len(gallery_embs)]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=gallery_pts[:, 0], y=gallery_pts[:, 1],
        mode="markers", name="Genuine Gallery",
        marker=dict(color="rgba(0,240,255,0.8)", size=10, line=dict(color="#00f0ff", width=1.5), symbol="circle"),
    ))
    cx, cy = float(gallery_pts[:, 0].mean()), float(gallery_pts[:, 1].mean())
    fig.add_trace(go.Scatter(
        x=[cx], y=[cy], mode="markers", name="Centroid",
        marker=dict(color="#00f0ff", size=16, symbol="star", line=dict(color="#ffffff", width=1)),
    ))
    q_color = "#10b981" if granted else "#ef4444"
    q_sym   = "circle-dot" if granted else "x"
    fig.add_trace(go.Scatter(
        x=[query_pt[0]], y=[query_pt[1]], mode="markers", name=label,
        marker=dict(color=q_color, size=16, symbol=q_sym, line=dict(color="white", width=2)),
    ))
    fig.update_layout(
        title=dict(text="🧠 Embedding Space — PCA Projection", font=dict(color="#f8fafc", size=14)),
        paper_bgcolor="rgba(15,23,42,0.0)", plot_bgcolor="rgba(15,23,42,0.4)",
        font=dict(color="#94a3b8", size=11), legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color="#e2e8f0")),
        xaxis=dict(title="PC-1", gridcolor="rgba(255,255,255,0.05)", zeroline=False),
        yaxis=dict(title="PC-2", gridcolor="rgba(255,255,255,0.05)", zeroline=False),
        margin=dict(l=20, r=20, t=45, b=20), height=370,
    )
    st.plotly_chart(fig, use_container_width=True)

def leaderboard_record(attacker_name: str, min_dist: float, verdict: str, query_stats: dict) -> dict:
    from datetime import datetime
    return {
        "name":      attacker_name,
        "min_dist":  round(min_dist, 4),
        "verdict":   verdict,
        "hold_mean": round(query_stats.get("hold_mean", 0), 1),
        "flight_mean": round(query_stats.get("flight_mean", 0), 1),
        "ts":        datetime.now().strftime("%H:%M:%S"),
    }

def build_keystroke_recorder(mode: str, prompt_text: str = "") -> Optional[str]:
    """
    Render keystroke recorder for *mode* ('enroll' or 'test').

    Architecture (no copy/paste required):
      • An HTML iframe captures keydown/keyup timestamps in JS memory.
      • On every keyup (debounced 150 ms), JS pushes the JSON payload to the
        hidden Streamlit textarea below via window.parent DOM access.
        (Both served from the same localhost origin, so access is permitted.)
      • The user just types, then clicks the form submit button.  Pauses in
        the middle of the sentence are fine — all events accumulate.
      • The "Clear & Retype" button resets both the iframe and the parent.
    """
    if not prompt_text:
        prompt_text = CHALLENGE_PHRASES[0]
    ss_key       = f"ksr_payload_{mode}"    # stable session_state key
    widget_key   = f"ksr_textarea_{mode}"   # stable Streamlit widget key
    component_id = f"ksr_{mode}"
    aria_lbl     = f"ksr_hidden_{mode}"     # JS in iframe finds parent textarea by this

    html_code = f"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap');
  body {{ margin:0; font-family:'Outfit',sans-serif; background:transparent; color:#e2e8f0; }}
  .ksr-prompt {{
    background: rgba(15,23,42,0.6); backdrop-filter: blur(10px);
    border:1px solid rgba(255,255,255,0.05); border-radius:12px;
    padding:14px 18px; font-size:14px; margin-bottom:12px;
    border-left:4px solid #00f0ff; line-height:1.6;
    box-shadow:0 4px 6px -1px rgba(0,0,0,.1),0 2px 4px -1px rgba(0,0,0,.06);
  }}
  .ksr-phrase {{ color:#00f0ff; font-weight:700; letter-spacing:.2px; }}
  textarea#ta_{component_id} {{
    width:100%; box-sizing:border-box; border-radius:10px;
    padding:14px; font-size:15px;
    border:1px solid rgba(148,163,184,.2);
    background:rgba(15,23,42,.8); color:#f8fafc; resize:vertical;
    min-height:90px; outline:none; transition:all .3s ease;
    font-family:'Outfit',sans-serif;
    box-shadow:inset 0 2px 4px 0 rgba(0,0,0,.06);
  }}
  textarea#ta_{component_id}:focus {{
    border-color:#00f0ff;
    box-shadow:0 0 0 3px rgba(0,240,255,.15),inset 0 2px 4px 0 rgba(0,0,0,.06);
  }}
  textarea#ta_{component_id}::placeholder {{ color:#475569; }}
  .ksr-bar {{ margin-top:10px; display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .ksr-status {{
    font-size:12px; padding:6px 16px; border-radius:20px; font-weight:600;
    flex:1; text-align:center; text-transform:uppercase; letter-spacing:.5px;
    transition:all .3s ease;
  }}
  .ksr-warn   {{ background:rgba(245,158,11,.15);  color:#f59e0b; border:1px solid rgba(245,158,11,.3); }}
  .ksr-ok     {{ background:rgba(16,185,129,.15);  color:#10b981; border:1px solid rgba(16,185,129,.3); box-shadow:0 0 10px rgba(16,185,129,.1); }}
  .ksr-synced {{ background:rgba(0,240,255,.1);    color:#00f0ff; border:1px solid rgba(0,240,255,.25); box-shadow:0 0 8px rgba(0,240,255,.1); }}
  .ksr-btn-clear {{
    padding:7px 16px; font-size:12px; background:rgba(239,68,68,.15);
    color:#ef4444; border:1px solid rgba(239,68,68,.3); border-radius:8px;
    cursor:pointer; font-weight:600; transition:all .2s ease; white-space:nowrap;
  }}
  .ksr-btn-clear:hover {{ background:rgba(239,68,68,.28); box-shadow:0 0 8px rgba(239,68,68,.2); }}
  .ksr-hint {{ font-size:11px; color:#64748b; margin-top:7px; font-style:italic; }}
</style>
<div>
  <div class="ksr-prompt">
    Type this sentence naturally:<br>
    <span class="ksr-phrase">"{prompt_text}"</span>
  </div>
  <textarea id="ta_{component_id}"
    placeholder="Start typing here — keystrokes are captured automatically. No copy/paste needed."
    spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off">
  </textarea>
  <div class="ksr-bar">
    <span class="ksr-status ksr-warn" id="status_{component_id}">0 keystrokes</span>
    <button class="ksr-btn-clear" id="btn_clear_{component_id}">&#8635; Clear &amp; Retype</button>
  </div>
  <div class="ksr-hint">&#128274; Keystroke data syncs live &mdash; just type naturally, then click the button below.</div>
</div>
<script>
(function() {{
  var ta         = document.getElementById("ta_{component_id}");
  var statusEl   = document.getElementById("status_{component_id}");
  var btnClear   = document.getElementById("btn_clear_{component_id}");
  var key_events = [];
  var key_times  = {{}};
  var last_keyup = null;
  var syncTimer  = null;

  // Push JSON payload to the hidden Streamlit textarea in parent frame.
  // window.parent.document is accessible because Streamlit serves the iframe
  // and the parent page from the same localhost origin (no CORS block).
  function pushToParent(payload) {{
    try {{
      var allTA = window.parent.document.querySelectorAll("textarea");
      for (var i = 0; i < allTA.length; i++) {{
        if ((allTA[i].getAttribute("aria-label") || "") === "{aria_lbl}") {{
          var setter = Object.getOwnPropertyDescriptor(
            window.parent.HTMLTextAreaElement.prototype, "value"
          ).set;
          setter.call(allTA[i], payload);
          allTA[i].dispatchEvent(new Event("input", {{ bubbles: true }}));
          return true;
        }}
      }}
    }} catch(e) {{}}
    return false;
  }}

  function syncNow() {{
    if (key_events.length === 0) return;
    var ok = pushToParent(JSON.stringify(key_events));
    if (ok) {{
      statusEl.className = "ksr-status ksr-synced";
      statusEl.innerText = key_events.length + " keystrokes \u2714 ready \u2014 click the button below";
    }}
  }}

  ta.addEventListener("keydown", function(e) {{
    if (!e.repeat) {{ key_times[e.key] = performance.now(); }}
  }});

  ta.addEventListener("keyup", function(e) {{
    var t0 = key_times[e.key];
    if (t0 !== undefined) {{
      var rel    = performance.now();
      var hold   = (rel - t0)   / 1000.0;
      var flight = last_keyup !== null ? (t0 - last_keyup) / 1000.0 : 0.0;
      last_keyup = rel;
      delete key_times[e.key];
      var kc = e.key.length === 1 ? e.key.charCodeAt(0) : 0;
      key_events.push([kc / 255.0, hold, flight]);
      var n = key_events.length;
      statusEl.className = "ksr-status " + (n >= 200 ? "ksr-ok" : "ksr-warn");
      statusEl.innerText  = n + " keystrokes" + (n < 200 ? " (need \u2265200)" : " \u2714 syncing...");
      clearTimeout(syncTimer);
      syncTimer = setTimeout(syncNow, 150);
    }}
  }});

  btnClear.addEventListener("click", function() {{
    key_events = []; key_times = {{}}; last_keyup = null; ta.value = "";
    statusEl.className = "ksr-status ksr-warn";
    statusEl.innerText = "0 keystrokes";
    pushToParent("");
  }});
}})();
</script>
"""
    st_html(html_code, height=245, scrolling=False)

    # Hide the raw textarea visually — JS keeps it populated so the Streamlit
    # form submit button (Authenticate / Save) reads the latest payload.
    st.markdown(
        f"""<style>
        div[data-testid="stTextArea"]:has(textarea[aria-label="{aria_lbl}"]) {{
          height:0!important; overflow:hidden!important;
          margin:0!important; padding:0!important;
          opacity:0!important; pointer-events:none!important;
        }}
        </style>""",
        unsafe_allow_html=True,
    )

    current_in_ss = st.session_state.get(ss_key, "")
    pasted = st.text_area(
        aria_lbl,               # becomes aria-label — JS searches for this exact string
        value=current_in_ss,
        key=widget_key,
        height=68,
        placeholder="",
        label_visibility="visible",   # keep visible so aria-label is written to DOM
    )

    cleaned = (pasted or "").strip()
    st.session_state[ss_key] = cleaned
    return cleaned or None


# â”€â”€â”€ Bootstrap: load model once at startup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

st.title("Type2Branch - Keystroke Authentication")
st.caption("Initializing model and artifacts; first load may take 1-3 minutes on shared DGX.")

threshold_info      = load_threshold_artifact()
checkpoint_path     = resolve_checkpoint_path(threshold_info)
checkpoint_fingerprint = short_sha256(checkpoint_path)
checkpoint_mtime    = os.path.getmtime(checkpoint_path) if os.path.exists(checkpoint_path) else -1.0
runtime_candidates  = build_runtime_candidates(threshold_info)

bootstrap_error: Optional[str] = None
with st.spinner("Loading Type2Branch model..."):
    try:
        model, descriptor, has_weights, model_load_error, runtime_source = load_best_model(
            runtime_candidates, checkpoint_path, checkpoint_fingerprint
        )
    except Exception as exc:
        bootstrap_error = f"Model bootstrap failed: {exc}"
        model = None
        descriptor = {"SEQUENCE_LENGTH": runtime_candidates[0][0], "INPUT_FEATURES": runtime_candidates[0][1]}
        has_weights = False
        model_load_error = bootstrap_error
        runtime_source = "bootstrap_fallback"

SEQ_LEN = descriptor["SEQUENCE_LENGTH"]
N_FEAT  = descriptor["INPUT_FEATURES"]

checkpoint_hash  = checkpoint_fingerprint
threshold_value  = threshold_info["threshold"] if threshold_info else None
threshold_source = threshold_info["path"]      if threshold_info else "not found"

threshold_shape_warning: Optional[str] = None
if threshold_info:
    t_seq  = int(threshold_info.get("sequence_length", SEQ_LEN))
    t_feat = int(threshold_info.get("input_features",  N_FEAT))
    if (t_seq, t_feat) != (SEQ_LEN, N_FEAT):
        threshold_shape_warning = (
            f"Threshold artifact shape ({t_seq},{t_feat}) != model shape ({SEQ_LEN},{N_FEAT}). "
            "Threshold disabled - use sidebar override."
        )
        threshold_value = None

startup_warnings: List[str] = []
if bootstrap_error:
    startup_warnings.append(bootstrap_error)
if model_load_error:
    startup_warnings.append(model_load_error)
if not has_weights:
    startup_warnings.append(f"Checkpoint not usable at: {checkpoint_path}")

# â”€â”€â”€ Session-state initialisation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())
if "enrollments" not in st.session_state:
    enr, enr_warnings = load_enrollments(SEQ_LEN, N_FEAT)
    st.session_state.enrollments         = enr
    st.session_state.enrollment_warnings = enr_warnings
# Challenge phrase nonce — rotated each new browser session (anti-replay)
if "challenge_phrase" not in st.session_state:
    import random as _random
    st.session_state.challenge_phrase = _random.choice(CHALLENGE_PHRASES)
# Per-user auth fail counters and lockout
if "auth_consec_fails" not in st.session_state:
    st.session_state.auth_consec_fails = {}
if "auth_locked" not in st.session_state:
    st.session_state.auth_locked = {}
if "stepup_required" not in st.session_state:
    st.session_state.stepup_required = {}
# Leaderboard: tracks ALL auth attempts for Challenge Mode
if "leaderboard" not in st.session_state:
    st.session_state.leaderboard = []
# Per-user enrollment timing baseline
if "enrollment_timing" not in st.session_state:
    st.session_state.enrollment_timing = {}

# â”€â”€â”€ Page header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
st.markdown("Enroll typing profiles and authenticate users by their unique keystroke rhythm.")

c_a, c_b, c_c = st.columns(3)
c_a.metric("Weights loaded", "Yes" if has_weights else "No")
c_b.metric("Model shape",    f"{SEQ_LEN} x {N_FEAT}")
c_c.metric("Users enrolled", len(st.session_state.enrollments))

if model_load_error:
    st.error(f"Model load error - {model_load_error}")
if not has_weights:
    st.warning(f"Checkpoint not loaded. Expected at: `{checkpoint_path}`")
for warning in startup_warnings:
    if warning:
        st.warning(warning)
if threshold_value is None and threshold_info is None:
    st.warning("No threshold artifact found. Enable **Override threshold** in the sidebar.")
if threshold_shape_warning:
    st.warning(threshold_shape_warning)
for w in st.session_state.get("enrollment_warnings", []):
    st.warning(w)

# â”€â”€â”€ Sidebar â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
with st.sidebar:
    st.subheader("🔐 Production Controls")

    enrolled_now  = st.session_state.get("enrollments", {})
    all_embs_flat = [emb for embs in enrolled_now.values() for emb in embs]
    _auto_threshold = 14.5
    _intra_mean, _intra_std = None, None
    if len(all_embs_flat) >= 2:
        import itertools as _it
        pairwise = [float(np.linalg.norm(a - b))
                    for a, b in _it.combinations(all_embs_flat, 2)]
        _intra_mean = float(np.mean(pairwise))
        _intra_std  = float(np.std(pairwise))
        _p90        = float(np.percentile(pairwise, PERSONAL_THRESHOLD_PERCENTILE))
        _auto_threshold = _p90 * THRESHOLD_SAFETY_MARGIN

    st.caption(f"Auto-calibrated (p{PERSONAL_THRESHOLD_PERCENTILE} x {THRESHOLD_SAFETY_MARGIN}x): `{_auto_threshold:.4f}`")
    tightness = st.slider(
        "Tightness multiplier", min_value=0.5, max_value=1.5, value=1.0, step=0.05,
        help="< 1.0 = stricter. > 1.0 = looser. Keep 1.0 for auto."
    )
    DEMO_THRESHOLD = _auto_threshold * tightness

    st.divider()
    enable_llm_gate = st.checkbox("Enable LLM/Paste gate", value=True)
    llm_threshold   = st.number_input(
        "LLM gate threshold", min_value=0.0, max_value=1.0,
        value=float(os.environ.get("TYPE2BRANCH_APP_LLM_THRESHOLD", "0.35")),
        step=0.01, format="%.2f", disabled=not enable_llm_gate,
    )
    st.divider()
    st.subheader("Continuous Auth Settings")
    decision_window = st.number_input("Decision Window (smoothing)", min_value=1, value=5, step=1)
    window_stride   = st.number_input("Window Stride (keystrokes)",  min_value=1, value=10, step=1)
    st.divider()
    if not has_weights:
        st.error("Weights missing — enroll/auth disabled.")
    st.caption(f"Effective threshold: `{DEMO_THRESHOLD:.4f}` ({tightness:.2f}x)")
    st.caption(f"Checkpoint: `{os.path.basename(checkpoint_path)}`")
    st.caption(f"sha256: `{checkpoint_hash}`")

effective_threshold: Optional[float] = DEMO_THRESHOLD

tab_enroll, tab_auth = st.tabs(["📋 Enroll Users", "🔑 Authenticate"])

# ══════════════════════════════════════════════════════════════════
# TAB 1 — ENROLL
# ══════════════════════════════════════════════════════════════════
with tab_enroll:
    st.subheader("Enroll a user's typing profile")
    st.info(
        f"**Minimum {MIN_ENROLLMENT_TEMPLATES} samples required** before authentication is enabled (10-15 recommended for better accuracy). "
        "Enroll at different times of day for best security."
    )

    if not has_weights:
        st.error(f"Model weights not loaded. Expected at: `{checkpoint_path}`")
    else:
        enroll_phrase = CHALLENGE_PHRASES[0]
        with st.form("enroll_form"):
            uid = st.text_input("User ID", placeholder="e.g. alice", key="enroll_uid_input")
            st.markdown("#### Step 1 — Type the phrase and copy the payload")
            enroll_payload = build_keystroke_recorder("enroll", enroll_phrase)
            st.markdown("#### Step 2 — Save the sample")
            save_enroll_clicked = st.form_submit_button(
                "Save Enrollment Sample", type="primary", use_container_width=True
            )

        if save_enroll_clicked:
            uid_clean = (uid or "").strip()
            if not uid_clean:
                st.warning("Enter a User ID before saving.")
            elif not enroll_payload:
                st.warning("No payload. Type the sentence -> Copy JSON -> Paste -> Save.")
            else:
                try:
                    raw_evts = json.loads(enroll_payload)
                except Exception:
                    raw_evts = []

                plausible, plaus_reason = check_typing_plausibility(raw_evts)
                if plausible:
                    st.error(f"Suspicious input: **{plaus_reason}**\nType naturally and retry.")
                else:
                    with st.spinner("Computing embedding..."):
                        seq, _ = process_raw_events(enroll_payload, SEQ_LEN, N_FEAT)
                    if seq is not None:
                        batch = np.expand_dims(seq, axis=0)
                        emb   = model.predict(batch, verbose=0)[0].astype(np.float32)
                        existing = st.session_state.enrollments.get(uid_clean, [])
                        is_outlier, outlier_reason = is_enrollment_outlier(emb, existing)
                        if is_outlier:
                            st.warning(
                                f"Sample quality warning: {outlier_reason}\n\n"
                                "Sample **not saved**. Please retype more naturally."
                            )
                        else:
                            updated = update_rolling_gallery(existing, emb)
                            st.session_state.enrollments[uid_clean] = updated
                            # Store / update timing baseline for XAI
                            t_stats = extract_timing_stats(raw_evts)
                            if t_stats:
                                old_t = st.session_state.enrollment_timing.get(uid_clean, {})
                                if old_t:
                                    for k in ("hold_mean", "hold_std", "flight_mean", "flight_std"):
                                        old_t[k] = 0.7 * old_t.get(k, t_stats[k]) + 0.3 * t_stats[k]
                                    st.session_state.enrollment_timing[uid_clean] = old_t
                                else:
                                    st.session_state.enrollment_timing[uid_clean] = t_stats
                            try:
                                save_enrollments(
                                    st.session_state.enrollments,
                                    SEQ_LEN, N_FEAT, checkpoint_hash, threshold_source,
                                )
                            except Exception as exc:
                                st.error(f"Disk save failed ({exc}). In-memory only.")
                            n       = len(updated)
                            quality = compute_enrollment_quality(updated)
                            eqs_pct = int(quality["score"] * 100)
                            thr_val = quality["threshold"]
                            st.success(f"Saved. **{uid_clean}** now has **{n}** template(s).")
                            if n >= MIN_ENROLLMENT_TEMPLATES:
                                if eqs_pct >= 60:
                                    st.success(
                                        f"Profile strength: **{eqs_pct}%** | "
                                        f"Personal threshold: **{thr_val}** | "
                                        "Authentication **enabled**!"
                                    )
                                else:
                                    st.warning(
                                        f"Profile strength: **{eqs_pct}%** (Needs to be >= 60%) | "
                                        f"Authentication **disabled** due to poor quality. Please delete bad samples or re-enroll for a consistent baseline."
                                    )
                            else:
                                st.info(
                                    f"Profile strength: {eqs_pct}% | "
                                    f"Add **{MIN_ENROLLMENT_TEMPLATES - n} more sample(s)** to enable auth."
                                )
                            st.session_state["ksr_payload_enroll"] = ""
                            st.rerun()

    st.divider()
    st.subheader("Enrolled users")
    all_enrollments = st.session_state.enrollments
    if not all_enrollments:
        st.info("No users enrolled yet.")
    else:
        for u in sorted(all_enrollments):
            embs = all_enrollments[u]
            n    = len(embs)
            q    = compute_enrollment_quality(embs)
            ready = "Ready" if n >= MIN_ENROLLMENT_TEMPLATES else f"{n}/{MIN_ENROLLMENT_TEMPLATES}"
            thr_disp = f"{q['threshold']}" if q['threshold'] else "not yet"
            st.write(
                f"- **{u}**: {n} template(s) [{ready}] | "
                f"Strength: {int(q['score']*100)}% | Threshold: `{thr_disp}`"
            )
        st.divider()
        c1, c2 = st.columns(2)
        with c1:
            del_uid = st.selectbox("Delete user", options=[""] + sorted(all_enrollments), key="del_uid_select")
            if st.button("Delete selected", disabled=not del_uid):
                if del_uid in st.session_state.enrollments:
                    del st.session_state.enrollments[del_uid]
                    save_enrollments(st.session_state.enrollments, SEQ_LEN, N_FEAT, checkpoint_hash, threshold_source)
                    st.success(f"Deleted '{del_uid}'.")
                    st.rerun()
        with c2:
            confirm_clear = st.checkbox("Confirm wipe all", key="confirm_clear")
            if st.button("Clear all enrollments", disabled=not confirm_clear):
                st.session_state.enrollments = {}
                save_enrollments({}, SEQ_LEN, N_FEAT, checkpoint_hash, threshold_source)
                st.success("All enrollments cleared.")
                st.rerun()

# ══════════════════════════════════════════════════════════════════
# TAB 2 — AUTHENTICATE  (production hardened)
# ══════════════════════════════════════════════════════════════════
with tab_auth:
    st.subheader("Authenticate a user")

    if not st.session_state.enrollments:
        st.info("No enrolled users. Go to **Enroll Users** tab first.")
    elif not has_weights:
        st.error("Model weights not loaded — cannot authenticate.")
    else:
        valid_users   = sorted(st.session_state.enrollments.keys())
        selected_user = st.selectbox("Select user", options=valid_users, key="auth_user_select")
        user_embs     = st.session_state.enrollments[selected_user]
        n_templates   = len(user_embs)

        # Per-user personal threshold
        personal_thr = compute_personal_threshold(user_embs)
        if personal_thr is not None:
            active_thr = personal_thr * tightness
            st.caption(
                f"Personal threshold for *{selected_user}*: `{active_thr:.4f}` "
                f"(p{PERSONAL_THRESHOLD_PERCENTILE}={personal_thr/THRESHOLD_SAFETY_MARGIN:.4f} "
                f"x {THRESHOLD_SAFETY_MARGIN}x safety x {tightness:.2f}x tightness)"
            )
        else:
            active_thr = effective_threshold
            st.caption(f"Using global threshold `{active_thr:.4f}` (need >= 2 templates for personal threshold).")

        # Lockout check
        is_locked = st.session_state.auth_locked.get(selected_user, False)
        if is_locked:
            st.error(
                f"**{selected_user}** is locked out due to repeated auth failures. "
                "Contact an admin or re-enroll."
            )
            if st.button("Admin unlock (demo only)", key="unlock_btn"):
                st.session_state.auth_locked[selected_user]       = False
                st.session_state.auth_consec_fails[selected_user] = 0
                st.session_state.stepup_required[selected_user]   = False
                st.rerun()

        elif n_templates < MIN_ENROLLMENT_TEMPLATES:
            st.warning(
                f"**{selected_user}** only has {n_templates} template(s). "
                f"Need **{MIN_ENROLLMENT_TEMPLATES}** minimum. Add more in the Enroll tab."
            )
        elif compute_enrollment_quality(user_embs)["score"] < 0.60:
            quality_score = int(compute_enrollment_quality(user_embs)["score"] * 100)
            st.warning(
                f"**{selected_user}**'s enrollment quality ({quality_score}%) is too low. "
                f"Needs to be >= 60%. Please delete bad samples or re-enroll for a consistent baseline."
            )
        else:
            if st.session_state.stepup_required.get(selected_user, False):
                st.warning(
                    "Step-up verification required. Anomalous typing detected in a previous attempt. "
                    "Retype the phrase to confirm your identity."
                )

            # Anti-replay nonce challenge
            session_phrase = st.session_state.challenge_phrase
            st.markdown(
                f"<div style='background:rgba(0,240,255,0.05);border:1px solid rgba(0,240,255,0.2);"
                f"border-radius:10px;padding:12px 18px;margin-bottom:12px;'>"
                f"<span style='color:#94a3b8;font-size:0.8rem;text-transform:uppercase;letter-spacing:1px;'>"
                f"Session Challenge Phrase</span><br>"
                f"<b style='color:#00f0ff;font-size:1.05rem;'>\"{session_phrase}\"</b></div>",
                unsafe_allow_html=True,
            )

            with st.form("auth_form"):
                st.markdown("#### Type the challenge phrase above and copy the payload")
                test_payload = build_keystroke_recorder("test", session_phrase)
                st.markdown("#### Run authentication")
                auth_clicked = st.form_submit_button("Authenticate", type="primary", use_container_width=True)

            if auth_clicked:
                if not test_payload:
                    st.warning("No payload. Type -> Copy JSON -> Paste -> Authenticate.")
                else:
                    # Gate 1: Plausibility
                    try:
                        raw_evts = json.loads(test_payload)
                    except Exception:
                        raw_evts = []
                    suspicious, sus_reason = check_typing_plausibility(raw_evts)
                    if suspicious:
                        st.error(f"ACCESS DENIED — Suspicious input: {sus_reason}")
                        fails = st.session_state.auth_consec_fails.get(selected_user, 0) + 1
                        st.session_state.auth_consec_fails[selected_user] = fails
                        if fails >= MAX_CONSEC_FAILS_LOCKOUT:
                            st.session_state.auth_locked[selected_user] = True
                            st.rerun()
                    else:
                        with st.spinner("Running continuous inference..."):
                            windows, decoded_txt = process_continuous_events(
                                test_payload, SEQ_LEN, N_FEAT, int(window_stride)
                            )

                        if windows is not None and len(windows) > 0:
                            llm_blocked     = False
                            blocked_step    = -1
                            window_scores   = []
                            smoothed_scores = []
                            consec_high     = 0
                            thr = float(active_thr)

                            for step, seq in enumerate(windows):
                                # Gate 2: LLM/paste detection
                                if enable_llm_gate:
                                    is_llm, _, llm_conf = detect_llm_paste.detect_llm_behavior(
                                        seq, threshold=float(llm_threshold)
                                    )
                                    if is_llm:
                                        llm_blocked  = True
                                        blocked_step = step
                                        break

                                # Gate 3: Biometric distance
                                batch      = np.expand_dims(seq, axis=0)
                                query_emb  = model.predict(batch, verbose=0)[0].astype(np.float32)
                                mean_dist, _ = gallery_distance(user_embs, query_emb)
                                window_scores.append(mean_dist)
                                start_idx  = max(0, len(window_scores) - int(decision_window))
                                smoothed   = float(np.mean(window_scores[start_idx:]))
                                smoothed_scores.append(smoothed)
                                if smoothed > thr:
                                    consec_high += 1
                                    if consec_high >= MAX_CONSEC_FAILS_STEPUP:
                                        blocked_step = step
                                        break
                                else:
                                    consec_high = 0

                            # Metrics
                            st.divider()
                            if smoothed_scores:
                                d1, d2, d3, d4 = st.columns(4)
                                _fs  = smoothed_scores[-1]
                                _gap = thr - _fs
                                d1.metric("Final Dist Score", f"{_fs:.4f}")
                                d2.metric("Personal Threshold", f"{thr:.4f}")
                                d3.metric("Gap (thr - score)", f"{_gap:.4f}",
                                          delta=f"{'SAFE' if _gap > 0 else 'BREACH'}",
                                          delta_color="normal")
                                d4.metric("Windows Analysed", len(smoothed_scores))

                            # Verdict
                            if llm_blocked:
                                st.error(f"## ACCESS DENIED — LLM/Paste attack (step {blocked_step+1})")
                                fails = st.session_state.auth_consec_fails.get(selected_user, 0) + 1
                                st.session_state.auth_consec_fails[selected_user] = fails
                                if fails >= MAX_CONSEC_FAILS_LOCKOUT:
                                    st.session_state.auth_locked[selected_user] = True
                                    st.error(f"{selected_user} is now locked out.")
                                    st.rerun()

                            elif blocked_step != -1:
                                fails = st.session_state.auth_consec_fails.get(selected_user, 0) + 1
                                st.session_state.auth_consec_fails[selected_user] = fails
                                if fails >= MAX_CONSEC_FAILS_LOCKOUT:
                                    st.session_state.auth_locked[selected_user] = True
                                    st.error(f"## ACCESS DENIED — {selected_user} locked out after {fails} failures.")
                                    st.rerun()
                                elif fails >= MAX_CONSEC_FAILS_STEPUP:
                                    st.session_state.stepup_required[selected_user] = True
                                    st.error(
                                        f"## ACCESS DENIED (attempt {fails}/{MAX_CONSEC_FAILS_LOCKOUT})\n\n"
                                        f"Score exceeded threshold `{thr:.4f}`."
                                    )
                                else:
                                    st.session_state.stepup_required[selected_user] = True
                                    st.warning(
                                        f"Step-up required — score anomaly detected "
                                        f"({fails}/{MAX_CONSEC_FAILS_STEPUP} soft warnings). "
                                        "Retype to confirm your identity."
                                    )
                            else:
                                # Success
                                is_verified = True

                                if not is_verified:
                                    fails = st.session_state.auth_consec_fails.get(selected_user, 0) + 1
                                    st.session_state.auth_consec_fails[selected_user] = fails
                                    if fails >= MAX_CONSEC_FAILS_LOCKOUT:
                                        st.session_state.auth_locked[selected_user] = True
                                        st.error(f"## ACCESS DENIED — {selected_user} locked out after {fails} failures.")
                                        st.rerun()
                                    else:
                                        st.error(f"## ACCESS DENIED (attempt {fails}/{MAX_CONSEC_FAILS_LOCKOUT})")
                                        st.info("Biometric verification failed. Please try again with a steady rhythm.")
                                else:
                                    # Reset failures on success
                                    st.session_state.auth_consec_fails[selected_user] = 0
                                    st.session_state.stepup_required[selected_user]   = False
                                    
                                    # Rolling gallery update
                                    if windows:
                                        last_emb = model.predict(
                                            np.expand_dims(windows[-1], axis=0), verbose=0
                                        )[0].astype(np.float32)
                                        updated = update_rolling_gallery(user_embs, last_emb)
                                        st.session_state.enrollments[selected_user] = updated
                                        try:
                                            save_enrollments(
                                                st.session_state.enrollments,
                                                SEQ_LEN, N_FEAT, checkpoint_hash, threshold_source,
                                            )
                                        except Exception:
                                            pass
                                    st.success("## ACCESS GRANTED")
                                    st.balloons()
                                    import random as _r
                                    st.session_state.challenge_phrase = _r.choice(CHALLENGE_PHRASES)

                    st.session_state["ksr_payload_test"] = ""

                    _q_stats = extract_timing_stats(raw_evts) if raw_evts else {}
                    _baseline = st.session_state.enrollment_timing.get(selected_user, {})
                    _verdict_str = "ACCESS GRANTED" if blocked_step == -1 and not llm_blocked and not suspicious else "ACCESS DENIED"
                    _granted = _verdict_str == "ACCESS GRANTED"

                    if _q_stats and _baseline:
                        with st.expander("🔬 Explainable AI — Timing Signature Breakdown", expanded=_verdict_str=="ACCESS DENIED"):
                            st.caption("This chart compares genuine baseline timing (blue) vs this attempt (red).")
                            _q_label = "Genuine User" if _granted else "Impostor"
                            render_xai_comparison(_q_stats, _baseline, label=_q_label)








