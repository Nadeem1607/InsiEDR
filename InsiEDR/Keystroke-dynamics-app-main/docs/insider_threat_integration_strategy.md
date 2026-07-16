# Strategy Document: Integrating Type2Branch-CA into an Insider Threat Detection Framework

**Author:** Raja Rajeswaran . A  
**Project:** Type2Branch-CA (Continuous Authentication)  
**Context:** Integration Proposal for the "Insider Threat" Module  

---

## 1. Executive Summary
Traditional Insider Threat detection systems rely on log analysis, file access monitoring, and network anomalies. However, they lack a critical component: **Positive Human Identification**. Type2Branch-CA addresses this by providing a continuous biometric "heartbeat." This document outlines the strategy for executing a transition from a standalone research project to a core security module for workstation integrity.

---

## 2. Core Value Proposition: The "Human Identity Layer"
In an Insider Threat context, Type2Branch provides three unique capabilities:

1.  **Workstation Hijacking Prevention:** Detects if an unauthorized individual sits at a logged-in workstation.
2.  **Credential Sharing Detection:** Identifies if an employee has shared their credentials with a peer, as the typing rhythm will not match the authorized baseline.
3.  **Bot/Automation Mitigation:** The Dual-Gate architecture (LLM Gate) identifies if an insider is using scripts or AI bots to perform automated actions that simulate human activity.

---

## 3. Integration Architecture

The following architecture defines how Type2Branch fits into a larger Security Operations Center (SOC) ecosystem:

### A. Data Collection Layer (The Sensor)
*   **Keystroke Service:** A background agent (developed from the `app.py` logic) that captures inter-key timings without recording the actual characters (preserving privacy).
*   **Privacy-Preserving Buffer:** Clears raw timestamps immediately after feature extraction.

### B. Analytical Layer (The Brain)
*   **Type2Branch Inference Engine:** Runs the dual-branch attention model to compute the `s_t` distance score.
*   **LLM Heuristic Engine:** Flags robotic/assisted input patterns.

### C. Orchestration Layer (The Controller)
*   **Decision Fusion:** Combines the Type2Branch score with other "Insider Threat" signals (e.g., suspicious file access, odd login times).
*   **Risk Score Generation:** Instead of a simple "Deny," the system outputs a **Biometric Confidence Score** (0.0 to 1.0) to the main module.

---

## 4. Execution Roadmap (Phased Approach)

### Phase 1: API-fication (Immediate)
*   **Task:** Decouple the inference logic from the Streamlit UI.
*   **Execution:** Create a lightweight FastAPI endpoint that accepts a keystroke timing JSON and returns a verification verdict.
*   **Outcome:** The "Insider Threat" module can now "query" Type2Branch for an identity check at any time.

### Phase 2: Behavioral Baselines (Short-term)
*   **Task:** Implement "Low-Touch" Enrollment.
*   **Execution:** Automate the enrollment process so the system learns the employee's rhythm during their first hour of work, creating an "Identity Profile" without explicit user training.

### Phase 3: Signal Fusion (Mid-term)
*   **Task:** Correlated Alerting.
*   **Execution:** If a user accesses a "Top Secret" folder, the Insider Threat module triggers a 10-step Type2Branch verification. If the rhythm doesn't match the folder owner's profile, the session is terminated.

---

## 5. Deployment Scenario: The "Unlocked Desk"
1.  **User A** (Authorized) leaves their desk to go to lunch without locking the screen.
2.  **User B** (Insider Threat) sits down and attempts to copy sensitive code to a USB drive.
3.  **Type2Branch** detects User B's typing rhythm within 4-5 keystrokes.
4.  The system raises a **Biometric Mismatch Alert**.
5.  The **Insider Threat Module** receives this alert and automatically freezes the USB port and locks the screen, demanding MFA.

---

## 6. Conclusion
By integrating Type2Branch-CA, the "Insider Threat" module gains a biological ground truth. It moves beyond "What is happening?" to "Who is doing it?", significantly hardening the perimeter against internal breaches.
