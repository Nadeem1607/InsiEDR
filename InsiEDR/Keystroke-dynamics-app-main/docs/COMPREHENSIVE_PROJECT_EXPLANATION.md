# Type2Branch: Comprehensive Project Explanation
*Your Definitive Guide to Answering Technical Panel Questions*

---

## 1. Project Overview & Philosophy
**Project Name:** Type2Branch: Dual-Gate Continuous Biometric Authentication
**The Core Problem:** Passwords can be stolen. Traditional continuous authentication models can be bypassed by AI (like ChatGPT) or macro scripts generating "perfect" typing data.
**The Solution:** A Dual-Gate defense system. Gate 1 identifies completely non-human synthetic data (like LLMs or copy-paste). Gate 2 uses Deep Metric Learning to uniquely identify the user's biological typing rhythm.

---

## 2. How the App Works: Step-by-Step

### Step 1: The Frontend (Keystroke Capture)
*   **What it does:** Captures every single key you press.
*   **How it works:** We inject custom JavaScript (`components.html`) into the user's browser.
*   **The Magic Modules:** Native JS Event Listeners (`keydown` and `keyup`).
*   **What the Panel Needs to Know:** We do *not* care about *what* the user is typing (the letters). We care about the **timestamps**. The JavaScript captures exactly when a key goes down, and when it goes up, in microsecond precision. We calculate **Hold-Time (HT)** (how long a key is pressed) and **Flight-Time (FT)** (time between keys). 

### Step 2: The UI Framework (`app.py`)
*   **What it does:** The main interactive web dashboard you see during the demo.
*   **How it works:** Built entirely on **Streamlit** (A Python dashboarding library).
*   **The Magic Modules:** `streamlit`, `pandas`, `altair` (for rendering UI charts).
*   **What the Panel Needs to Know:** Streamlit allows us to route the JavaScript timestamp data directly into a Python backend seamlessly without needing complex REST APIs or a separate Node.js server. 

### Step 3: Gate 1 - Synthetic Data Detection (`detect_llm_paste.py`)
*   **What it does:** The AI defense layer. It blocks robotic or copy-paste attacks.
*   **How it works:** This is a deterministic heuristics engine. It calculates the **Variance** of flight times. Humans *never* type with zero variance (we make micro-mistakes). Python scripts or copy-paste actions happen instantly with mathematically zero variance.
*   **The Magic Modules:** `numpy` (for fast variance and standard deviation mathematics).
*   **What the Panel Needs to Know:** If the variance is extremely low, or the typing speed is physically impossible for a human, Gate 1 flags it as "Unnatural Input" and the session is terminated instantly.

### Step 4: Gate 2 - Deep Biometric Verification (`model.py` & `app.py`)
*   **What it does:** Confirms you are who you say you are.
*   **How it works:** If you pass Gate 1, your keystrokes are grouped into arrays of 100 keys and sent into our **Type2Branch Deep Neural Network**.
*   **The Architecture:**
    1.  **Conv1D Layers:** These act like a magnifying glass, looking at short bursts of typing (like fast "th" or "er" bigrams).
    2.  **Bi-LSTM Layers:** (Bidirectional Long Short-Term Memory). This looks at the entire "rhythm" of the 100-key sequence, tracking how you speed up or slow down over a long sentence.
*   **The Magic Modules:** `tensorflow.keras`.
*   **What the Panel Needs to Know:** The AI outputs a **128-dimensional embedding** (a unique mathematical identity coordinate). We measure the Euclidean (L2) distance between this coordinate and your saved "Gallery" profile. If the distance is less than our threshold (`15.14`), you are verified. If it is greater, you are flagged as an Impostor!

---

## 3. Core Technologies & Modules (The Tech Stack)

If the panel asks what libraries you used, here is the exact list and *why* you used them:

*   **TensorFlow:** The core engine for building, training, and running our Deep Neural Network (Type2Branch).
*   **Streamlit:** Used to build the rapid-prototyping front-end application without needing React or Angular. 
*   **NumPy:** Essential for matrix operations, calculating L2 distances, variance, and manipulating the multi-dimensional dataset tensors.
*   **Pandas:** Used during the data ingestion phase (`ingest_aalto.py`) to parse massive CSV files into usable columns and structures.
*   **Matplotlib / Altair:** Used for graphing the FAR/FRR metrics and the live dashboard UI visualizations.
*   **Scikit-Learn (sklearn):** Used for calculating ROC curves, AUC scores, and the ECE calibration metrics for our novelty defense.

---

## 4. Explaining the Datasets
*   **Base Dataset:** We trained on the **Aalto Keystroke Dataset** (tens of thousands of users from Finland).
*   **Our Sub-Sampling:** Because real-world databases are massively imbalanced, we used *16,859 users* from the desktop pool, calculating evaluation scores over millions of permutations to achieve our **0.31% Equal Error Rate (EER)**.

---

## 5. Potential "Gotcha" Questions & Answers

**Q: "Did you use raw key presses (A, B, C) for authentication?"**
A: "No sir/ma'am. Using characters introduces extreme privacy risks (keylogging). We only capture the biological rhythm—the temporal 'Hold Time' and 'Flight Time'. The actual keys typed are irrelevant to our mathematical distance calculation."

**Q: "Why did you use Bi-LSTM instead of standard LSTM?"**
A: "Typing is highly contextual. The speed at which I release the 'T' key is heavily influenced by the fact that I am about to press the 'H' key in the word 'The'. Bidirectional LSTM looks both forwards and backwards in the sequence, allowing it to capture these contextual biological dependencies."

**Q: "Why do we need Gate 1 (LLM Detection)? Why wouldn't Type2Branch just block it anyway?"**
A: "Neural networks try to map patterns. A copy-pasted block of text from ChatGPT has a mathematically 'flat' or 'perfect' time signature. In some adversarial cases, if a deep learning model is fed 'perfect' data, it hallucinates a false positive. By placing a deterministic Gate 1 in front of the model, we guarantee that the Neural Network never wastes compute power attempting to classify an impossible biological rhythm."
