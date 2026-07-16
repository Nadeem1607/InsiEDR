from __future__ import annotations

from typing import Any, Dict, List


from heuristics.detector import detect_insider_threat

class RiskAggregator:
    """Aggregates multiple detector outputs into a single Risk Event."""

    def __init__(self, storage) -> None:
        self.storage = storage

    def summary(self) -> Dict[str, Any]:
        """Provides a statistical summary for dashboard metrics."""
        stats = self.storage.get_stats() if hasattr(self.storage, "get_stats") else {}
        return {
            "ok": True,
            "agents": stats.get("agents", 0),
            "logs": stats.get("logs", 0),
            "collector_results": stats.get("collector_results", 0),
            "anomalies": stats.get("anomalies", 0),
            "baselines": stats.get("baselines", 0),
        }

    def aggregate_detectors(self, detector_results: List[Dict[str, Any]], username: str = None, raw_features: dict = None) -> Dict[str, Any]:
        """
        Combines multiple detector outputs into a final risk assessment.
        Mathematically weighs detector agreement, confidence, and source quality.
        """
        if not detector_results:
            return {
                "risk_score": 0.0,
                "risk_level": "low",
                "summary": "No active detectors.",
                "correlated_signals_json": {}
            }

        total_weighted_score = 0.0
        total_confidence = 0.0
        anomalies_flagged = 0
        correlated_signals = {}
        reasons = []

        for result in detector_results:
            name = result.get("detector_name", "unknown")
            score = result.get("score", 0.0)
            conf = result.get("confidence", 0.0)
            
            # Source Quality Penalty: Penalize heuristic collectors (like file system hooks)
            is_heuristic = False
            for feat_name in result.get("feature_contributions", {}).keys():
                if "file" in feat_name.lower() or "usb" in feat_name.lower():
                    is_heuristic = True
                    break
                    
            weight = conf
            if is_heuristic:
                weight *= 0.5  # Require more corroboration for heuristic data
                result["reason"] += " (Heuristic Source Warning: Score penalized)"
            
            total_weighted_score += (score * weight)
            total_confidence += weight
            
            correlated_signals[name] = result

            if result.get("is_anomaly"):
                anomalies_flagged += 1
                reasons.append(result.get("reason", ""))

        # Calculate base aggregated score
        final_score = total_weighted_score / total_confidence if total_confidence > 0 else 0.0
        # Agreement Amplifier: If multiple disparate detectors flag an anomaly, amplify the risk
        if anomalies_flagged > 1:
            final_score *= (1.0 + (anomalies_flagged * 0.1))
        
        # Feature Group Correlation: Suppress isolated auth bursts
        if anomalies_flagged == 1 and correlated_signals.get("auth_burst", {}).get("is_anomaly"):
            final_score *= 0.6  # 40% penalty for isolated authentication bursts (no lateral movement)
            reasons.append("Isolated authentication burst with no correlated lateral movement (Risk suppressed).")

        # Cap at 100.0
        avg_score = total_weighted_score / total_confidence if total_confidence > 0 else 0.0
        max_score = max([r.get("score", 0.0) * r.get("confidence", 0.0) for r in detector_results]) if detector_results else 0.0
        
        # Blend max score (70%) with average score (30%) to prevent heavy dilution
        final_score = (max_score * 0.7) + (avg_score * 0.3)

        # Temporal Correlation (Memory Window)
        # Fetch the max risk score for the user in the past 4 hours
        if username and hasattr(self.storage, "get_max_risk_score_in_window"):
            past_max_score = self.storage.get_max_risk_score_in_window(username, 4)
            if final_score >= 40.0 and past_max_score >= 40.0:
                final_score *= 1.25  # Sustained Deviation Amplifier
                reasons.append(f"Sustained repeated anomaly pattern detected over the past 4 hours (Past Max: {past_max_score:.2f})")

        # Cap at 100.0
        final_score = min(final_score, 100.0)

        risk_level = "low"
        if final_score >= 80.0:
            risk_level = "critical"
        elif final_score >= 60.0:
            risk_level = "high"
        elif final_score >= 40.0:
            risk_level = "medium"
        elif final_score > 0.0 and final_score < 10.0:
            risk_level = "info"

        summary = "Normal behavior."
        if anomalies_flagged > 0:
            summary = " | ".join(r for r in reasons if r)

        # Inject CERT Threat Scenarios
        cert_scenarios = self._map_cert_scenarios(detector_results)
        correlated_signals["cert_scenarios"] = cert_scenarios

        # Execute Heuristics Engine to generate explicit Scenarios
        if raw_features:
            h_result = detect_insider_threat(raw_features)
            correlated_signals["heuristics"] = h_result
            
            # If heuristics triggered, append to summary for human-readability
            if h_result.get("scenario_count", 0) > 0:
                h_scenarios = " | ".join(d["scenario"] for d in h_result.get("detections", []))
                
                # False-Positive Suppression: If Heuristics explicitly classifies this as known 
                # "Normal/Low" behavior, override the unsupervised ML model's high score.
                if h_result.get("overall_severity") in ["LOW", "INFO"] and final_score > 30.0:
                    final_score = float(h_result.get("overall_score", 0.0))
                    risk_level = "low"
                    if final_score < 10.0:
                        risk_level = "info"
                    summary = f"Normal behavior ({h_scenarios}). ML false-positive suppressed."
                else:
                    if summary == "Normal behavior.":
                        summary = h_scenarios
                    else:
                        summary = f"{h_scenarios} | {summary}"

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "summary": summary,
            "correlated_signals_json": correlated_signals
        }

    def _map_cert_scenarios(self, detector_results: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        scenarios = []
        anomalous_features = set()
        
        # Only evaluate features that were actively flagged as an anomaly by at least one detector
        for result in detector_results:
            if result.get("is_anomaly"):
                for feat_name in result.get("feature_contributions", {}).keys():
                    anomalous_features.add(feat_name)
                    
        # Check for heuristic features to append VERIFY_REQUIRED
        has_heuristics = any(feat for feat in anomalous_features if "file_copy" in feat or "upload_count" in feat or "large_usb_transfer" in feat or "usb_file_transfer_count" in feat or "large_file_transfer_count" in feat)
        heuristic_tag = " [VERIFY_REQUIRED - Heuristic Source]" if has_heuristics else ""
                    
        # S1 & S2: IP Theft / Bulk Exfiltration (PDF: CRITICAL)
        s1_s2_device = {"usb_connect_count", "daily_files_to_removable_count", "external_drive_file_copy", "large_usb_transfer", "daily_device_usage_flag", "daily_files_to_removable_7d_sum", "usb_file_transfer_count"}
        s1_s2_http = {"job_search_site_visits"}
        
        intersect_s1_device = anomalous_features.intersection(s1_s2_device)
        intersect_s1_http = anomalous_features.intersection(s1_s2_http)
        
        if len(intersect_s1_device) >= 1 and len(intersect_s1_http) >= 1:
            scenarios.append({
                "id": "S1_S2", 
                "severity": "CRITICAL",
                "description": f"CERT S1/S2: WikiLeaks/IP Theft - USB Activity + Job Search{heuristic_tag} (Correlated: {', '.join(intersect_s1_device.union(intersect_s1_http))})"
            })
        elif "large_usb_transfer" in anomalous_features or "external_drive_file_copy" in anomalous_features or "daily_files_to_removable_7d_sum" in anomalous_features or "usb_file_transfer_count" in anomalous_features:
            scenarios.append({
                "id": "S1_S2_Partial", 
                "severity": "CRITICAL",
                "description": f"CERT S1/S2: USB Data Exfiltration{heuristic_tag} (Correlated: {', '.join(intersect_s1_device)})"
            })
            
        # S3: IT Sabotage (PDF: CRITICAL)
        s3_file = {"file_delete_count", "daily_file_delete_count"}
        s3_auth = {"after_hours_logon", "daily_failed_login_ratio", "edr_failed_auth_ratio_window", "edr_auth_burst_score"}
        
        intersect_s3_file = anomalous_features.intersection(s3_file)
        intersect_s3_auth = anomalous_features.intersection(s3_auth)
        
        if len(intersect_s3_file) >= 1 and len(intersect_s3_auth) >= 1:
            scenarios.append({
                "id": "S3", 
                "severity": "CRITICAL",
                "description": f"CERT S3: Admin Betrayal / IT Sabotage - Mass Delete + Auth Spikes (Correlated: {', '.join(intersect_s3_file.union(intersect_s3_auth))})"
            })
        elif "file_delete_count" in anomalous_features or "daily_file_delete_count" in anomalous_features:
            scenarios.append({
                "id": "S3_Partial", 
                "severity": "CRITICAL",
                "description": f"CERT S3: Mass File Deletion Before Exit (Correlated: {', '.join(intersect_s3_file)})"
            })
            
        # S4: Private Email Exfiltration (Partial) (PDF: CRITICAL, patched to HIGH)
        s4_keys = {"file_access_after_hours", "http_after_hours", "after_hours_logon"}
        intersect_s4 = anomalous_features.intersection(s4_keys)
        if len(intersect_s4) >= 2:
            scenarios.append({
                "id": "S4", 
                "severity": "HIGH",
                "description": f"CERT S4: Confidential Files via Private Email (Indirect Indicators){heuristic_tag} (Correlated: {', '.join(intersect_s4)})"
            })
            
        # S5: Restricted Browsing + Cloud Upload (PDF: CRITICAL)
        s5_http = {"file_sharing_site_visits"}
        s5_file = {"sensitive_file_access", "unusual_file_access_ratio"}
        
        intersect_s5_http = anomalous_features.intersection(s5_http)
        intersect_s5_file = anomalous_features.intersection(s5_file)
        
        if len(intersect_s5_http) >= 1 and len(intersect_s5_file) >= 1:
            scenarios.append({
                "id": "S5", 
                "severity": "CRITICAL",
                "description": f"CERT S5: Restricted File Browsing + Cloud Storage Upload{heuristic_tag} (Correlated: {', '.join(intersect_s5_http.union(intersect_s5_file))})"
            })
        elif "file_sharing_site_visits" in anomalous_features:
            scenarios.append({
                "id": "S5_Partial", 
                "severity": "HIGH",
                "description": f"CERT S5: Cloud Storage Upload Activity{heuristic_tag} (Correlated: {', '.join(intersect_s5_http)})"
            })
            
        return scenarios
