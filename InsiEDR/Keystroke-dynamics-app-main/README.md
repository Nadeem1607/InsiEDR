# Type2Branch-CA: Continuous Authentication and Insider Threat Detection

Companion source code for the **Type2Branch** architecture, extended with **Continuous Authentication (CA)** and **Insider Threat Detection** capabilities.

## Contributors
*   **Original Architecture:** Nahuel González, Giuseppe Stragapede, Ruben Vera-Rodriguez, Ruben Tolosana.
*   **CA Extension & Implementation:** **Raja Rajeswaran . A** (SASTRA Deemed University)

---

## 🚀 Overview
Type2Branch-CA is an advanced keystroke biometrics system that moves beyond simple login-time authentication. It provides a continuous biometric "heartbeat" that monitors the user's typing rhythm throughout a session.

### Key Features:
1.  **Dual-Gate Decision Rule:** Combines a Biometric Gate (Behavioral Verification) with an LLM Gate (Synthetic/Bot Detection).
2.  **Continuous Monitoring:** Detects session hijacking or unauthorized workstation access within 4.2 keystroke steps.
3.  **Insider Threat Protection:** Explicitly designed to identify credential sharing and automated bot attacks.

---

## 📁 Repository Structure
*   `app.py`: Streamlit-based live demo with enrollment and continuous authentication.
*   `model.py`: Core Type2Branch neural network (Dual-branch Attention Model).
*   `evaluate_continuous.py`: Protocol logic for continuous evaluation and detection delay.
*   `detect_llm_paste.py`: Heuristic-based detection for non-human (LLM/Paste) typing patterns.
*   `docs/`: Comprehensive results, speaker notes, and integration strategies.
*   `results_ieee/figures/`: High-resolution performance curves (ROC, Calibration, Tradeoffs).

---

## 🛠️ Usage Instructions

### 1. Installation
```bash
pip install -r requirements.txt
```

### 2. Running the Live Demo
```bash
streamlit run app.py
```
*The app allows you to enroll a biometric profile and then test the continuous authentication gate in real-time.*

### 3. Running Continuous Evaluation
To reproduce the continuous authentication metrics (Detection Rate, Delay, etc.):
```bash
python evaluate_continuous.py <dataset_name> --output-dir results_continuous
```

---

## 🛡️ Insider Threat Integration
This project is designed to be integrated into larger corporate security modules. For a detailed roadmap on how to deploy this in a Security Operations Center (SOC), see:
👉 [Insider Threat Integration Strategy](docs/insider_threat_integration_strategy.md)

---

## 📊 Results Summary
*   **Equal Error Rate (EER):** 0.31% (State-of-the-art performance on 16,000+ users).
*   **Detection Rate:** 99.6% against impostor attacks.
*   **Detection Delay:** ~4 keystrokes (ultra-fast session hijacking detection).

---

## 🔗 References
*   [Original Paper (IEEE TIFS)](https://arxiv.org/abs/2405.01088)
*   [KVC-onGoing Competition](https://ieeexplore.ieee.org/document/10386557)
