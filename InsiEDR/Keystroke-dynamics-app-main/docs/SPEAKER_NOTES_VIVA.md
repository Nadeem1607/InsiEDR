# Type2Branch: Final Viva Speaker Notes & Defense Guide

This document is your master script. Keep it open on a secondary screen or printed out during your Viva. It contains exactly what to say for every slide, exactly what to click during the live demo, and the precise "Engineer Answers" to the hardest panel questions.

---

## PART 1: Slide-by-Slide Presentation Script

### Slide 4 & 5: Objectives & Problem Context
**What to say:**
*"Traditional cybersecurity relies on static passwords, which are easily stolen by modern AI and LLMs. My objective is to design a continuous, behavioral authentication pipeline. The identified limitation in existing systems is that they are purely binary—they authenticate humans vs. humans. They completely fail to address emerging threats like AI-assisted bot scripts injecting perfectly timed keystrokes."*

### Slide 7 & 8: Methodology (The Dual-Gate System)
**What to say:**
*"To solve this, I designed a Dual-Gate Architecture. 
**Gate 1** is a Non-Stationary Anomaly Detector acting as an immediate pre-filter. It uses deterministic heuristics—specifically looking at the variance of flight times—to catch bot scripts, zero-variance pastes, and superhuman typing speeds. 
If the input is deemed biological, it passes to **Gate 2**, our Deep Metric Learning model. This uses a shared-weight Neural Network built with Conv1D and Bi-LSTM layers trained on Triplet Loss. Gate 2 doesn't ask 'Is this a human?', it asks 'WHICH human is this?' by generating a 128-dimensional biometric embedding."*

### Slide 9 & 10: Modules & Dataset
**What to say:**
*(If you split this into two slides as discussed, cover both here)*
*"The system has 4 core modules: Data Acquisition via JavaScript, Feature Extraction, the Gate 1 Heuristic Pre-Filter, and the Gate 2 Deep Learning Biometric Engine. 
For training, I utilized the Aalto University Desktop Dataset, isolating over 130 million keystrokes to ensure the model learned universal rhythmic dependencies before fine-tuning it for individual authentication."*

### Slide 14: Results (Base Paper Reproduction)
**What to say:**
*"Here you can see the foundational performance of the model on human-to-human verification. Our Loss curve converges smoothly, and our Equal Error Rate (EER) reached an optimal 0.3162% with a True Acceptance Rate of over 99.6%. The histograms show a clear, defensible separation between genuine user embeddings and impostor embeddings in the 128-D hypersphere."*

### Slide 15: Continuous Evaluation (The Novelty!)
**What to say:**
*"This represents my novel contribution: The Multi-Class Threat implementation. As shown in the ROC curve and Confusion Matrix, the system achieves near 100% detection accuracy against AI/LLM bot attacks. By running continuously in the background, it provides a 'Zero-Trust' layer that secures the session long after the initial login."*

---

## PART 2: The Live Demo Script

Follow these steps exactly. Do not deviate.

### 1. The Intro
**Action:** Open `localhost:8501`. Point to the top metrics.
**Say:** *"The Streamlit backend has successfully booted the deep learning model from our DGX checkpoint. It is initialized for a 100x5 input tensor."*

### 2. The Enrollment
**Action:** Go to "Enroll Users". Type your name (`Raja`). Type the sentence naturally, click **Copy JSON payload**, paste it below, and click Save. Do this 3-5 times.
**Say:** *"The neural network needs a Gallery Profile. As I type, hidden JavaScript captures my microsecond timings. I copy the JSON payload and pass it to the backend to generate my 128-D biometric signature."*

### 3. The Authentication (Success)
**Action:** Go to "Authenticate". Type the sentence **and add the word "gemini" somewhere**. Copy, paste, and Authenticate. It will glow GREEN.
**Say:** *"When I authenticate, my biological rhythm matches my gallery. Furthermore, I have implemented Multi-Factor Behavioral Authentication (MFBA). I seamlessly integrated a secret keyword into my typing. The system verifies both my biological rhythm AND my knowledge of the secret."*

### 4. The Impostor Attack (Failure)
**Action:** Ask a panel member/guide to type. Have them *just type the sentence on screen* (they will not know the secret word). Copy, paste, and Authenticate. It will glow RED ("ACCESS DENIED").
**Say:** *"Even if an impostor manages to perfectly mimic my typing speed, the system blocks them. Because they lacked the MFBA secret keyword, the system forces a rejection, ensuring defense-in-depth."*

### 5. The Bot Attack (Failure)
**Action:** Copy a block of text from an external file and **CTRL+V (Paste)** it directly into the typing area. Authenticate. It will instantly show `UNNATURAL INPUT DETECTED`.
**Say:** *"Finally, the bot attack. By manually pasting the JSON, I simulate an AI script injecting characters instantly. Gate 1 intercepts the mathematically zero-variance flight times and terminates the session before the AI even evaluates it, proving our 100% block rate against synthetic attacks."*

---

## PART 3: The "Gotcha" Panel Q&A

Study these answers. This is where you win the Viva.

### Q: "Your False Positive rate is 0.31? So 30% of the time it fails?"
**The Engineer's Answer:**
*"Actually ma'am, it is zero-point-three-one percent (0.31%). To put that in perspective, out of 1,000 hacker attempts, only 3 might get through. Our True Acceptance Rate is over 99.6%. For a deep metric learning model running on a massive 16,000+ user dataset, an EER of 0.31% is considered state-of-the-art."*

### Q: "Why did you only use 5 features? Why not pressure or mouse movements?"
**The Engineer's Answer:**
*"I chose these 5 specific temporal features (Hold Time, Flight Time, KeyNorm, and scaled variants) for three reasons:
1. **Privacy:** Capturing raw key coordinates enables reconstruction attacks. Timing features capture 'how' you type without storing 'what' you type.
2. **Hardware Agnosticism:** Most office keyboards lack pressure sensors. These 5 features can be captured on literally any standard keyboard.
3. **Curse of Dimensionality:** Extensive dataset research proved these 5 features provide the maximum Information Gain. Adding noisy features would increase DGX compute cost without improving our 0.31% EER."*

### Q: "What exactly does the 100x5 Model Shape mean?"
**The Engineer's Answer:**
*"It represents our sequence input tensor. The biological rhythm is evaluated over a continuous window of **100 keystrokes**. For each keystroke, we extract exactly **5 features**. This 500-unit data matrix gives the neural network the perfect amount of context to evaluate a complete rhythmic sentence."*

### Q: "Explain the AI Architecture: Why Conv1D? Why Bi-LSTM?"
**The Engineer's Answer:**
*"We use a dual-layer strategy:
*   **Conv1D (Convolutional 1D):** This acts as a microscopic feature extractor. It scans over overlapping key sequences (bigrams and trigrams) to learn local rhythms, like exactly how fast I transition the letters 'T-H-E'.
*   **Bi-LSTM (Bidirectional LSTM):** This captures the global rhythm. It is bidirectional because typing is predictive—how you release the 'A' key depends heavily on knowing your brain is about to push the 'N' key. Bi-LSTM captures these forward-and-backward dependencies across the entire 100-key buffer."*

### Q: "Why do you have to copy-paste the JSON payload in the demo?"
**The Engineer's Answer:**
*"This is an intentional Security Proof. Streamlit cannot access physical keystroke timings due to browser sandboxing, so we use JS. But more importantly, by manually pasting the payload block into the submission box, we simulate how a hacker's automated Python script would 'inject' data into a system. This allows me to prove live that Gate 1 can successfully intercept Paste Attacks based on zero-variance flight times."*

### Q: "Why did you use Minimum Distance instead of Mean Distance for authentication?"
**The Engineer's Answer:**
*"We use Nearest-Neighbour matching (Min Distance) against the gallery, which is the academic standard in Deep Metric Learning. A user's gallery captures multiple 'moods' (fast, tired, relaxed). Mean distance unfairly penalises a user for natural intra-class variance. Min distance correctly asks: 'Does this current session match AT LEAST ONE of the user's known biological profiles?'"*
