# Type2Branch Viva Results Summary

## Primary Performance Metric
**Equal Error Rate (EER): 0.31%**
*This means out of 1000 attempts, the system only makes ~3 mistakes. This is state-of-the-art for keystroke biometrics.*

### Detailed Statistics
- **Calibrated Threshold:** 15.14
- **True Acceptance Rate (TAR):** 99.68%
- **Evaluation Dataset:** 16,859 Users (Aalto Merged)
- **Model Efficiency:** < 50ms inference time

### Why 0.31%?
The Type2Branch architecture uses a "Dual-Gate" logic:
1. **Gate 1 (LLM Detector):** Intercepts synthetic/bot patterns with nearly 100% precision.
2. **Gate 2 (Biometric Net):** Extracts a 128-dimension feature vector (embedding) from your specific flight-time and hold-time rhythm variations. Because we trained on 16k+ users, the model generates an "Identity Space" where you are mathematically distant from everyone else!

### Final Recommendation for Panel Presentation
Show the **Biometric_Curve.png** and point to where the red and blue lines cross at the bottom (0.0031). That is your EER. Highlight that this is done *without* asking for a new password—it secures the user's *existing* rhythm.
