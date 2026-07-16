import numpy as np

def detect_llm_behavior(keystroke_chunk, threshold=0.35):
    """
    Analyzes a chunk of keystrokes for LLM-Assisted / Bot / Paste patterns.
    Uses multiple heuristics with confidence scoring.
    """
    confidence = 0.0
    reasons = []
    
    # Remove zero-padding rows where all key values are 0 (Keycode, HT, FT = 0)
    valid_mask = np.any(keystroke_chunk[:, :3] != 0, axis=1)
    chunk = keystroke_chunk[valid_mask]
    
    if len(chunk) < 5:
        # If there are almost no real keystrokes, we can't reliably detect bots
        return False, None, 0.0

    flight_times = chunk[:, 2]
    hold_times = chunk[:, 1]
    
    # Rule 1: Paste Detection
    # Fast typists often have negative flight times (key rollover).
    # Programmatic pastes usually have exactly 0.0 or very small positive flight times.
    paste_mask = (flight_times >= -0.001) & (flight_times < 0.005)
    near_zero_ft = np.sum(paste_mask)
    paste_ratio = near_zero_ft / len(flight_times)
    
    if near_zero_ft > 10:
        confidence += 0.4
        reasons.append("PASTE_DETECTED")
    elif paste_ratio > 0.15:
        confidence += 0.2
        reasons.append("PARTIAL_PASTE")
        
    # Rule 2: Burst/Speed Detection (Superhuman Speed)
    avg_ft = float(np.mean(flight_times))
    ft_variance = float(np.var(flight_times))
    
    if avg_ft < 0.08 and ft_variance < 0.001:
        confidence += 0.3
        reasons.append("SYNTHETIC_RHYTHM")
    elif avg_ft < 0.03:
        confidence += 0.35
        reasons.append("SUPERHUMAN_SPEED")
        
    # Rule 3: Hold Time Uniformity
    ht_std = float(np.std(hold_times))
    
    if ht_std < 0.005 and np.mean(hold_times) > 0:
        confidence += 0.25
        reasons.append("UNIFORM_HOLD_TIME")
        
    # Rule 4: Bigram Uniformity
    if len(flight_times) > 2:
        ft_diffs = np.abs(np.diff(flight_times))
        bigram_variance = float(np.var(ft_diffs))
        
        if bigram_variance < 0.0005 and avg_ft < 0.15:
            confidence += 0.2
            reasons.append("BIGRAM_UNIFORMITY")
            
    # Rule 5: Burst Pattern Detection
    if len(flight_times) > 10:
        fast_mask = flight_times < 0.01
        slow_mask = flight_times > 0.5
        
        transitions = 0
        for i in range(1, len(flight_times)):
            if fast_mask[i-1] and slow_mask[i]:
                transitions += 1
        
        if transitions >= 3:
            confidence += 0.2
            reasons.append("BURST_PATTERN")
            
    # Rule 6: N-gram Timing Entropy
    if len(flight_times) > 5:
        bins = np.linspace(0, 0.5, 20)
        digitized = np.digitize(flight_times, bins)
        _, counts = np.unique(digitized, return_counts=True)
        probs = counts / counts.sum()
        entropy = -np.sum(probs * np.log2(probs + 1e-10))
        
        if entropy < 1.5:
            confidence += 0.15
            reasons.append("LOW_ENTROPY")
            
    confidence = min(confidence, 1.0)
    
    # Cast to bool so json/streamlit serialization doesn't complain
    is_llm = bool(confidence >= threshold)
    reason = " | ".join(reasons) if reasons else None
    
    return is_llm, reason, confidence
