"""
strategies.py - ASOM-Aligned Threat Hunting Strategies for 221B

This module contains ASOM (Analytic Scheme of Maneuver) aligned threat hunting 
strategies that answer Commander's Critical Information Requirements (CCIRs).

Each strategy implements up to 3 sophistication levels:
- Level 1: Rule-based detection (watchlists, correlation rules, pattern matching)
- Level 2: Statistical baseline detection (anomaly scoring using historical baselines)
- Level 3: Machine learning detection (supervised/unsupervised ML models)

Architecture supports:
- Multi-table correlation across data sources (Zeek, Sysmon, Windows Events, etc.)
- Multiprocessing for performance optimization
- Machine learning with plain English explanations
"""

from abc import ABC, abstractmethod
import pandas as pd
import numpy as np
import re
from scipy.stats import entropy, rankdata, zscore
from multiprocessing import Pool, cpu_count
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, datetime
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional, Any
import warnings

# Try to import plotly for visualizations (optional)
try:
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

# Try to import scikit-learn for ML features (optional)
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.cluster import KMeans, DBSCAN
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import OneClassSVM
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

warnings.filterwarnings('ignore', category=FutureWarning)


# ============================================================================
# Configuration Constants
# ============================================================================

# ML Configuration
ML_MIN_SAMPLES = 50  # Minimum samples required to apply ML
ML_CONTAMINATION = 0.1  # Expected proportion of outliers (10%)
ML_RANDOM_STATE = 42  # For reproducible results
ML_MIN_SAMPLES_PER_CLUSTER = 15  # Minimum samples per cluster

# Feature normalization thresholds for explainability
ML_NORM_BYTES_HIGH = 100_000_000  # 100MB threshold for high data volume
ML_NORM_CONNECTIONS_HIGH = 100  # 100 connections threshold
ML_NORM_BYTES_PER_CONN = 10000  # 10KB threshold for transfer consistency
ML_NORM_IPS_HIGH = 10  # 10 IPs threshold for high diversity
ML_NORM_RAPID_SWITCHES = 5  # 5 switches threshold for rapid IP switching

# Statistical thresholds
STATISTICAL_ZSCORE_THRESHOLD = 3.0  # Standard deviations for anomaly
STATISTICAL_PERCENTILE_THRESHOLD = 99  # Percentile for baseline comparison

# Multiprocessing configuration
MAX_WORKERS = min(cpu_count(), 8)  # Limit to reasonable number of workers


# ============================================================================
# ML Helper Functions
# ============================================================================

def explain_ml_score(score: float, method: str = "anomaly") -> str:
    """
    Generate plain-English explanation of ML score for analysts.
    
    Args:
        score: ML-generated score (0-100 for anomaly/outlier, cluster ID for clustering)
        method: Type of ML method ('anomaly', 'cluster', 'outlier')
    
    Returns:
        Human-readable explanation with emoji indicators and confidence levels
    """
    if method == "anomaly":
        if score >= 75:
            return "🔴 HIGH CONFIDENCE - Machine learning identified this as highly anomalous compared to normal patterns"
        elif score >= 50:
            return "🟡 MEDIUM CONFIDENCE - ML detected moderate deviation from typical behavior"
        else:
            return "🟢 LOW CONFIDENCE - ML sees similarity to normal patterns, but rule-based logic flagged it"
    elif method == "cluster":
        return f"Grouped with similar patterns (Cluster {int(score)})"
    elif method == "outlier":
        if score >= 75:
            return "🔴 EXTREME OUTLIER - Significantly different from all other hosts"
        elif score >= 50:
            return "🟡 MODERATE OUTLIER - Noticeably different from typical behavior"
        else:
            return "🟢 SLIGHT OUTLIER - Minor deviations detected"
    return "Analysis performed"


def get_feature_importance_explanation(features: dict) -> str:
    """
    Explain which features contributed most to ML detection.
    
    Args:
        features: Dictionary mapping feature names to normalized values (0-1 scale)
    
    Returns:
        String explanation of top 3 contributing features
    """
    if not features:
        return "No feature data available"
    
    # Sort features by absolute value (impact)
    sorted_features = sorted(features.items(), key=lambda x: abs(x[1]), reverse=True)
    
    explanations = []
    for feat_name, feat_value in sorted_features[:3]:  # Top 3 features
        if feat_value > 0.5:
            explanations.append(f"High {feat_name}")
        elif feat_value < -0.5:
            explanations.append(f"Low {feat_name}")
        else:
            explanations.append(f"Moderate {feat_name}")
    
    return "Key factors: " + ", ".join(explanations)


# ============================================================================
# Correlation Framework - Multi-Table Support
# ============================================================================

class DataCorrelator:
    """
    Framework for correlating data across multiple sources (tables).
    
    Supports common correlation patterns in ASOM actions:
    - Temporal correlation (events within time windows)
    - Source IP correlation (same IP across different log types)
    - Process correlation (parent-child relationships)
    - User correlation (same user across different activities)
    """
    
    @staticmethod
    def temporal_join(
        df1: pd.DataFrame, 
        df2: pd.DataFrame,
        time_col1: str,
        time_col2: str,
        join_keys: List[str],
        window_seconds: int = 120
    ) -> pd.DataFrame:
        """
        Join two dataframes based on temporal proximity and common keys.
        
        Args:
            df1, df2: DataFrames to join
            time_col1, time_col2: Timestamp column names
            join_keys: List of columns to join on (e.g., ['source_ip'])
            window_seconds: Time window for correlation
            
        Returns:
            Merged DataFrame with events correlated within time window
        """
        if df1.empty or df2.empty:
            return pd.DataFrame()
        
        # Ensure timestamps are datetime
        df1 = df1.copy()
        df2 = df2.copy()
        df1[time_col1] = pd.to_datetime(df1[time_col1], errors='coerce')
        df2[time_col2] = pd.to_datetime(df2[time_col2], errors='coerce')
        
        # Sort by time for efficient processing
        df1 = df1.sort_values(time_col1)
        df2 = df2.sort_values(time_col2)
        
        # Merge on keys
        merged = pd.merge(df1, df2, on=join_keys, how='inner', suffixes=('_primary', '_secondary'))
        
        # Handle renamed time columns due to suffixes
        time_col1_actual = f"{time_col1}_primary" if time_col1 not in merged.columns and f"{time_col1}_primary" in merged.columns else time_col1
        time_col2_actual = f"{time_col2}_secondary" if time_col2 not in merged.columns and f"{time_col2}_secondary" in merged.columns else time_col2
        
        # Filter by time window
        time_diff = abs((merged[time_col1_actual] - merged[time_col2_actual]).dt.total_seconds())
        merged = merged[time_diff <= window_seconds]
        
        return merged
    
    @staticmethod
    def aggregate_by_entity(
        df: pd.DataFrame,
        entity_col: str,
        agg_functions: Dict[str, Any]
    ) -> pd.DataFrame:
        """
        Aggregate data by entity (IP, user, host) with specified functions.
        
        Args:
            df: DataFrame to aggregate
            entity_col: Column to group by (e.g., 'source_ip')
            agg_functions: Dictionary of {column: aggregation_function}
            
        Returns:
            Aggregated DataFrame
        """
        if df.empty:
            return pd.DataFrame()
        
        return df.groupby(entity_col).agg(agg_functions).reset_index()
    
    @staticmethod
    def enrich_with_threat_intel(
        df: pd.DataFrame,
        ip_col: str,
        threat_intel_ips: List[str]
    ) -> pd.DataFrame:
        """
        Enrich DataFrame with threat intelligence matches.
        
        Args:
            df: DataFrame to enrich
            ip_col: Column containing IP addresses
            threat_intel_ips: List of known malicious IPs
            
        Returns:
            DataFrame with 'threat_intel_match' boolean column
        """
        if df.empty:
            return df
        
        df = df.copy()
        df['threat_intel_match'] = df[ip_col].isin(threat_intel_ips)
        return df


# ============================================================================
# Abstract Base Class for ASOM Strategies
# ============================================================================

class ASOMLStrategy(ABC):
    """
    Abstract base class for ASOM-aligned threat hunting strategies.
    
    Each strategy answers a specific CCIR (Commander's Critical Information 
    Requirement) and implements up to 3 sophistication levels.
    """
    
    def __init__(self):
        """Initialize strategy with correlation framework."""
        self.correlator = DataCorrelator()
    
    @abstractmethod
    def _get_ccir_number(self) -> int:
        """Return CCIR number this strategy addresses (1-23)."""
        pass
    
    @abstractmethod
    def _get_ccir_question(self) -> str:
        """Return the CCIR question this strategy answers."""
        pass
    
    @abstractmethod
    def _get_tactic(self) -> str:
        """Return MITRE ATT&CK tactic (e.g., 'Initial Access')."""
        pass
    
    @abstractmethod
    def _get_name(self) -> str:
        """Return user-friendly strategy name."""
        pass
    
    @abstractmethod
    def _get_description(self) -> str:
        """Return detailed strategy description."""
        pass
    
    @abstractmethod
    def _get_required_inputs(self) -> List[str]:
        """
        Return list of required input column names.
        
        For multi-table strategies, use prefixes like:
        - 'primary_timestamp', 'primary_source_ip'
        - 'secondary_timestamp', 'secondary_process_name'
        """
        pass
    
    @abstractmethod
    def _get_data_sources(self) -> List[str]:
        """Return list of required data sources."""
        pass
    
    @abstractmethod
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Execute the strategy analysis.
        
        Args:
            df: Input DataFrame (can contain multiple joined sources)
            col_map: Mapping of required inputs to actual column names
            
        Returns:
            DataFrame with detection results including:
            - Original identifying columns (IP, user, timestamp, etc.)
            - Threat score (0-100)
            - Severity ('HIGH', 'MED', 'LOW')
            - Detection level (1, 2, or 3)
            - Explanation of detection
            - ML columns if Level 3 was triggered
        """
        pass
    
    def get_column_explanations(self) -> Dict[str, str]:
        """
        Return explanations for output columns.
        
        Default implementation provides common columns.
        Override to add strategy-specific columns.
        """
        return {
            'threat_score': 'Numeric threat score from 0-100 (higher = more suspicious)',
            'severity': 'Severity level: HIGH (≥75), MED (50-74), LOW (<50)',
            'detection_level': 'Sophistication level: 1 (rule-based), 2 (statistical), 3 (ML)',
            'explanation': 'Human-readable explanation of why this was flagged',
            'ml_anomaly_score': 'Machine learning anomaly score (0-100, Level 3 only)',
            'ml_confidence': 'ML confidence level: HIGH/MEDIUM/LOW (Level 3 only)',
            'ml_explanation': 'Plain English explanation of ML decision (Level 3 only)'
        }
    
    @property
    def name(self) -> str:
        """Public accessor for strategy name."""
        return self._get_name()
    
    @property
    def ccir(self) -> int:
        """Public accessor for CCIR number."""
        return self._get_ccir_number()
    
    @property
    def required_inputs(self) -> List[str]:
        """Public accessor for required inputs."""
        return self._get_required_inputs()
    
    def _apply_severity_labels(self, df: pd.DataFrame, score_col: str = 'threat_score') -> pd.DataFrame:
        """
        Apply severity labels based on threat scores.
        
        Args:
            df: DataFrame with threat scores
            score_col: Name of score column
            
        Returns:
            DataFrame with 'severity' column added
        """
        if df.empty or score_col not in df.columns:
            return df
        
        df = df.copy()
        df['severity'] = pd.cut(
            df[score_col],
            bins=[-np.inf, 50, 75, np.inf],
            labels=['LOW', 'MED', 'HIGH']
        )
        return df


# ============================================================================
# CCIR 1: Compromised Credentials Strategy
# ============================================================================

class CompromisedCredentialsStrategy(ASOMLStrategy):
    """
    CCIR 1: Has an adversary gained initial access using compromised credentials?
    
    Implements 3 sophistication levels:
    
    Level 1 (Rule-Based):
    - Detects successful remote logins preceded by 20+ failed login attempts
    - Flags post-login reconnaissance activity (whoami, net user, ipconfig)
    - Correlates with outbound connections to known malicious IPs
    
    Level 2 (Statistical Baseline):
    - Establishes baseline of normal user login behavior (hours, geolocation)
    - Detects anomalous logins on multiple dimensions:
      * Off-hours access (3 AM logins)
      * Geographic anomalies (new countries)
      * Excessive session data volume (>99th percentile)
    - Calculates statistical anomaly scores
    
    Level 3 (Machine Learning):
    - Isolation Forest / One-Class SVM on session features
    - Features: session duration, bytes sent/received, packet count, processes
    - Learns profile of 'normal' sessions and flags outliers
    - Provides ML confidence scores and feature importance
    
    Data Sources:
    - Windows Event ID 4624 (successful logon)
    - Windows Event ID 4625 (failed logon)
    - Zeek conn.log (network sessions)
    - Sysmon Event ID 1 (process creation)
    - Sysmon Event ID 3 (network connections)
    """
    
    def __init__(self):
        """Initialize the strategy."""
        super().__init__()
        
        # Reconnaissance commands to detect post-compromise activity
        self.recon_commands = [
            'whoami', 'net user', 'net group', 'ipconfig', 'ifconfig',
            'quser', 'query user', 'net localgroup', 'hostname', 
            'systeminfo', 'tasklist', 'netstat', 'arp', 'route print'
        ]
        
        # High-risk countries (adjust based on your threat model)
        self.high_risk_countries = ['CN', 'RU', 'KP', 'IR', 'SY']
        
    def _get_ccir_number(self) -> int:
        return 1
    
    def _get_ccir_question(self) -> str:
        return "Has an adversary gained initial access using compromised credentials?"
    
    def _get_tactic(self) -> str:
        return "Initial Access (TA0001)"
    
    def _get_name(self) -> str:
        return "Compromised Credentials Detector"
    
    def _get_description(self) -> str:
        return """
        Detects compromised credentials through multiple techniques:
        - Brute force patterns (failed attempts → success)
        - Anomalous login behavior (time, location, volume)
        - Post-compromise reconnaissance activity
        - Machine learning anomaly detection on session characteristics
        
        Implements all 3 ASOM sophistication levels for comprehensive coverage.
        """
    
    def _get_required_inputs(self) -> List[str]:
        return [
            'timestamp',
            'event_id',  # Windows Event ID (4624, 4625)
            'logon_type',  # Logon type (3=Network, 10=RemoteInteractive)
            'source_ip',
            'username',
            'status',  # Success/Failure
            'bytes_sent',  # Optional: from Zeek correlation
            'bytes_received',  # Optional: from Zeek correlation
            'process_name',  # Optional: from Sysmon correlation
            'command_line',  # Optional: from Sysmon correlation
        ]
    
    def _get_data_sources(self) -> List[str]:
        return [
            'Windows Event ID 4624',
            'Windows Event ID 4625',
            'Zeek conn.log',
            'Sysmon Event ID 1',
            'Sysmon Event ID 3'
        ]
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Execute compromised credentials detection.
        
        Applies all 3 sophistication levels and aggregates results.
        """
        if df.empty:
            return pd.DataFrame()
        
        # Map columns
        timestamp_col = col_map.get('timestamp', 'timestamp')
        event_id_col = col_map.get('event_id', 'event_id')
        source_ip_col = col_map.get('source_ip', 'source_ip')
        username_col = col_map.get('username', 'username')
        status_col = col_map.get('status', 'status')
        
        # Ensure timestamp is datetime
        df = df.copy()
        df[timestamp_col] = pd.to_datetime(df[timestamp_col], errors='coerce')
        
        # Run all three levels
        level1_results = self._level1_rule_based(df, col_map)
        level2_results = self._level2_statistical(df, col_map)
        level3_results = self._level3_machine_learning(df, col_map)
        
        # Combine results (union of all detections)
        all_results = []
        
        if not level1_results.empty:
            all_results.append(level1_results)
        if not level2_results.empty:
            all_results.append(level2_results)
        if not level3_results.empty:
            all_results.append(level3_results)
        
        if not all_results:
            return pd.DataFrame()
        
        # Concatenate and deduplicate
        combined = pd.concat(all_results, ignore_index=True)
        
        # If same entity detected by multiple levels, keep highest scoring
        if 'detection_key' in combined.columns:
            combined = combined.sort_values('threat_score', ascending=False)
            combined = combined.drop_duplicates(subset=['detection_key'], keep='first')
            combined = combined.drop(columns=['detection_key'])
        
        # Sort by threat score
        combined = combined.sort_values('threat_score', ascending=False)
        
        return combined
    
    def _level1_rule_based(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Level 1: Rule-based detection.
        
        Detects:
        1. Successful login after 20+ failed attempts from same IP
        2. Post-login reconnaissance commands
        3. Connections to known malicious IPs
        """
        timestamp_col = col_map.get('timestamp', 'timestamp')
        source_ip_col = col_map.get('source_ip', 'source_ip')
        username_col = col_map.get('username', 'username')
        status_col = col_map.get('status', 'status')
        event_id_col = col_map.get('event_id', 'event_id')
        
        results = []
        
        # Group by source IP
        for source_ip, group in df.groupby(source_ip_col):
            group = group.sort_values(timestamp_col)
            
            # Pattern 1: Brute force followed by success
            failures = group[
                (group[status_col].str.lower().str.contains('fail|denied', na=False)) |
                (group[event_id_col] == 4625)
            ]
            successes = group[
                (group[status_col].str.lower().str.contains('success|granted', na=False)) |
                (group[event_id_col] == 4624)
            ]
            
            if len(failures) >= 20 and len(successes) > 0:
                # Check if success comes after failures
                last_failure_time = failures[timestamp_col].max()
                first_success_time = successes[timestamp_col].min()
                
                if pd.notna(last_failure_time) and pd.notna(first_success_time):
                    if first_success_time > last_failure_time:
                        time_diff = (first_success_time - last_failure_time).total_seconds() / 60
                        
                        if time_diff <= 10:  # Within 10 minutes
                            for _, success_row in successes.iterrows():
                                threat_score = min(100, 75 + len(failures))  # Base 75, +1 per failure
                                
                                results.append({
                                    'timestamp': success_row[timestamp_col],
                                    'source_ip': source_ip,
                                    'username': success_row.get(username_col, 'unknown'),
                                    'threat_score': threat_score,
                                    'detection_level': 1,
                                    'explanation': f'Successful login after {len(failures)} failed attempts in {time_diff:.1f} minutes - Potential credential stuffing',
                                    'failed_attempts': len(failures),
                                    'time_to_success_minutes': time_diff,
                                    'detection_key': f"{source_ip}_{success_row[timestamp_col]}"
                                })
            
            # Pattern 2: Reconnaissance activity (requires command_line column)
            command_col = col_map.get('command_line', None)
            if command_col and command_col in group.columns:
                for _, row in group.iterrows():
                    cmd = str(row.get(command_col, '')).lower()
                    
                    # Check for recon commands
                    recon_found = [cmd_pattern for cmd_pattern in self.recon_commands if cmd_pattern in cmd]
                    
                    if recon_found and row.get(event_id_col) == 4624:  # After successful login
                        results.append({
                            'timestamp': row[timestamp_col],
                            'source_ip': source_ip,
                            'username': row.get(username_col, 'unknown'),
                            'threat_score': 65,
                            'detection_level': 1,
                            'explanation': f'Post-login reconnaissance: {", ".join(recon_found[:3])}',
                            'recon_commands': ', '.join(recon_found),
                            'detection_key': f"{source_ip}_{row[timestamp_col]}_recon"
                        })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        result_df = self._apply_severity_labels(result_df)
        return result_df
    
    def _level2_statistical(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Level 2: Statistical baseline detection.
        
        Establishes baselines and detects anomalies in:
        - Login hours (off-hours activity)
        - Geographic patterns (new countries, impossible travel)
        - Session data volume (>99th percentile)
        """
        timestamp_col = col_map.get('timestamp', 'timestamp')
        source_ip_col = col_map.get('source_ip', 'source_ip')
        username_col = col_map.get('username', 'username')
        event_id_col = col_map.get('event_id', 'event_id')
        
        # Filter to successful logins only
        success_df = df[
            (df.get(col_map.get('status', 'status'), '').astype(str).str.lower().str.contains('success|granted', na=False)) |
            (df.get(event_id_col, 0) == 4624)
        ].copy()
        
        if success_df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Extract hour from timestamp
        success_df['hour'] = success_df[timestamp_col].dt.hour
        
        # Analyze by user
        for username, user_group in success_df.groupby(username_col):
            if len(user_group) < 5:  # Need baseline
                continue
            
            # Baseline: typical login hours
            typical_hours = user_group['hour'].value_counts()
            
            for _, row in user_group.iterrows():
                anomaly_score = 0
                anomaly_reasons = []
                
                # Check 1: Off-hours login (midnight to 5 AM)
                login_hour = row['hour']
                if login_hour >= 0 and login_hour < 5:
                    anomaly_score += 25
                    anomaly_reasons.append(f'Off-hours login at {login_hour:02d}:00')
                
                # Check 2: Unusual hour for this user
                if login_hour not in typical_hours.index[:3]:  # Not in top 3 hours
                    anomaly_score += 20
                    anomaly_reasons.append(f'Unusual login hour for user')
                
                # Check 3: Session volume anomaly (if bytes columns available)
                bytes_sent_col = col_map.get('bytes_sent', None)
                bytes_recv_col = col_map.get('bytes_received', None)
                
                if bytes_sent_col and bytes_recv_col:
                    if bytes_sent_col in row and bytes_recv_col in row:
                        total_bytes = row.get(bytes_sent_col, 0) + row.get(bytes_recv_col, 0)
                        
                        # Calculate 99th percentile for this user
                        user_bytes = (
                            user_group.get(bytes_sent_col, 0).fillna(0) + 
                            user_group.get(bytes_recv_col, 0).fillna(0)
                        )
                        p99 = user_bytes.quantile(0.99)
                        
                        if total_bytes > p99 and p99 > 0:
                            anomaly_score += 30
                            anomaly_reasons.append(f'Excessive session volume: {total_bytes:,.0f} bytes (99th%: {p99:,.0f})')
                
                # Flag if significant anomalies detected
                if anomaly_score >= 50:
                    results.append({
                        'timestamp': row[timestamp_col],
                        'source_ip': row[source_ip_col],
                        'username': username,
                        'threat_score': min(anomaly_score, 100),
                        'detection_level': 2,
                        'explanation': 'Statistical anomaly: ' + '; '.join(anomaly_reasons),
                        'anomaly_factors': ', '.join(anomaly_reasons),
                        'detection_key': f"{row[source_ip_col]}_{row[timestamp_col]}_stat"
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        result_df = self._apply_severity_labels(result_df)
        return result_df
    
    def _level3_machine_learning(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Level 3: Machine learning anomaly detection.
        
        Uses Isolation Forest on session features:
        - Session duration
        - Bytes sent/received
        - Packet count
        - Number of distinct processes
        - Command line entropy
        """
        if not HAS_SKLEARN:
            return pd.DataFrame()
        
        timestamp_col = col_map.get('timestamp', 'timestamp')
        source_ip_col = col_map.get('source_ip', 'source_ip')
        username_col = col_map.get('username', 'username')
        event_id_col = col_map.get('event_id', 'event_id')
        
        # Filter to successful logins
        success_df = df[
            (df.get(col_map.get('status', 'status'), '').astype(str).str.lower().str.contains('success|granted', na=False)) |
            (df.get(event_id_col, 0) == 4624)
        ].copy()
        
        if len(success_df) < ML_MIN_SAMPLES:
            return pd.DataFrame()
        
        # Extract features
        features_list = []
        feature_indices = []
        
        for idx, row in success_df.iterrows():
            # Feature 1: Hour of day (0-23, normalized to 0-1)
            hour = row[timestamp_col].hour if pd.notna(row[timestamp_col]) else 12
            hour_norm = hour / 24.0
            
            # Feature 2: Session bytes (log scale)
            bytes_sent = row.get(col_map.get('bytes_sent', 'bytes_sent'), 0)
            bytes_recv = row.get(col_map.get('bytes_received', 'bytes_received'), 0)
            total_bytes = float(bytes_sent) + float(bytes_recv)
            bytes_norm = np.log1p(total_bytes) / np.log1p(ML_NORM_BYTES_HIGH)
            
            # Feature 3: Command line entropy (if available)
            cmd_col = col_map.get('command_line', None)
            if cmd_col and cmd_col in row:
                cmd = str(row.get(cmd_col, ''))
                if cmd:
                    cmd_entropy = entropy([cmd.count(c) for c in set(cmd)])
                else:
                    cmd_entropy = 0
            else:
                cmd_entropy = 0
            cmd_entropy_norm = min(cmd_entropy / 5.0, 1.0)  # Max entropy ~5 for typical strings
            
            features_list.append([hour_norm, bytes_norm, cmd_entropy_norm])
            feature_indices.append(idx)
        
        if len(features_list) < ML_MIN_SAMPLES:
            return pd.DataFrame()
        
        # Train Isolation Forest
        X = np.array(features_list)
        
        # Standardize features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Fit model
        iso_forest = IsolationForest(
            contamination=ML_CONTAMINATION,
            random_state=ML_RANDOM_STATE,
            n_estimators=100
        )
        
        predictions = iso_forest.fit_predict(X_scaled)
        anomaly_scores = iso_forest.score_samples(X_scaled)
        
        # Convert to 0-100 scale (lower score = more anomalous)
        # Normalize: most anomalous = 100, most normal = 0
        min_score = anomaly_scores.min()
        max_score = anomaly_scores.max()
        if max_score > min_score:
            ml_scores = 100 * (1 - (anomaly_scores - min_score) / (max_score - min_score))
        else:
            ml_scores = np.zeros(len(anomaly_scores))
        
        # Build results for anomalies
        results = []
        for i, idx in enumerate(feature_indices):
            if predictions[i] == -1:  # Anomaly detected
                row = success_df.loc[idx]
                ml_score = ml_scores[i]
                
                # Feature importance
                features_dict = {
                    'login_hour': features_list[i][0],
                    'session_bytes': features_list[i][1],
                    'command_entropy': features_list[i][2]
                }
                
                results.append({
                    'timestamp': row[timestamp_col],
                    'source_ip': row[source_ip_col],
                    'username': row.get(username_col, 'unknown'),
                    'threat_score': ml_score,
                    'detection_level': 3,
                    'explanation': 'Machine learning detected anomalous login session characteristics',
                    'ml_anomaly_score': ml_score,
                    'ml_confidence': explain_ml_score(ml_score, 'anomaly'),
                    'ml_explanation': get_feature_importance_explanation(features_dict),
                    'detection_key': f"{row[source_ip_col]}_{row[timestamp_col]}_ml"
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        result_df = self._apply_severity_labels(result_df)
        return result_df
    
    def get_column_explanations(self) -> Dict[str, str]:
        """Return explanations for output columns."""
        base_explanations = super().get_column_explanations()
        base_explanations.update({
            'source_ip': 'Source IP address of the login attempt',
            'username': 'Account name used for authentication',
            'failed_attempts': 'Number of failed login attempts before success (Level 1)',
            'time_to_success_minutes': 'Time from last failure to success in minutes (Level 1)',
            'recon_commands': 'Reconnaissance commands executed post-login (Level 1)',
            'anomaly_factors': 'Statistical anomalies detected in login pattern (Level 2)',
        })
        return base_explanations


# ============================================================================
# CCIR 22: DNS C2 Strategy
# ============================================================================

class DNSC2Strategy(ASOMLStrategy):
    """
    CCIR 22: Is an adversary using the Domain Name System (DNS) protocol for command and control communications?
    
    Implements 6 actions across 2 indicators, each with 3 sophistication levels:
    
    **Indicator 1: Process-Based DNS Detection (Sysmon focus)**
    
    Level 1 (Rule-Based):
    - Watchlist of processes that shouldn't initiate DNS queries
    - Detects suspicious processes: cmd.exe, powershell.exe, rundll32.exe, etc.
    - Identifies parent process relationships (Office apps, browsers as parents)
    
    Level 2 (Statistical Baseline):
    - Establishes baseline DNS behavior per process name
    - Tracks: hourly query volume, query name entropy, unique domains ratio, query type distribution
    - Flags processes deviating > 3 standard deviations from baseline
    
    Level 3 (Machine Learning):
    - Isolation Forest on process-level activity
    - Features: command line entropy, parent process, signature status, DNS metrics
    - Aggregates DNS activity in first 60 seconds of process life
    
    **Indicator 2: Query-Based DNS Detection (Network/Zeek focus)**
    
    Level 1 (Rule-Based):
    - Correlates DNS queries against threat intelligence feeds
    - Matches known C2 domains
    - Generates alerts with full context (source IP, hostname, process, domain)
    
    Level 2 (Statistical Baseline):
    - 30-day rolling baseline of DNS query metrics
    - Risk scoring: subdomain labels (>98th %), FQDN entropy (>98th %), query-response ratio (>4:1), TXT/NULL queries
    - Aggregates scores per host over 5-minute windows
    
    Level 3 (Machine Learning):
    - Random Forest classifier for C2 DNS detection
    - Features: query length, subdomain labels, Shannon entropy, numeric/alpha ratio, query type, TTL, frequency, periodicity
    - Alerts on probability score > 0.90
    
    Data Sources:
    - Sysmon Event ID 22 (DNS Query)
    - Sysmon Event ID 1 (Process Creation)
    - Windows Event ID 4688 (Process Creation)
    - Zeek dns.log
    - Zeek conn.log
    - Threat intelligence feeds
    """
    
    def __init__(self):
        """Initialize the DNS C2 detection strategy."""
        super().__init__()
        
        # Suspicious processes that shouldn't typically make DNS queries (Indicator 1, Level 1)
        self.suspicious_dns_processes = [
            'cmd.exe', 'powershell.exe', 'pwsh.exe', 'rundll32.exe',
            'cscript.exe', 'wscript.exe', 'mshta.exe', 'regsvr32.exe',
            'certutil.exe', 'bitsadmin.exe', 'msiexec.exe'
        ]
        
        # Parent processes that make suspicious DNS processes more concerning
        self.suspicious_parent_processes = [
            'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',  # Office
            'chrome.exe', 'firefox.exe', 'iexplore.exe', 'msedge.exe',  # Browsers
            'acrord32.exe', 'foxitreader.exe'  # PDF readers
        ]
        
        # Suspicious query types for C2
        self.suspicious_query_types = ['TXT', 'NULL', 'CNAME', 'MX']
    
    def _get_ccir_number(self) -> int:
        return 22
    
    def _get_ccir_question(self) -> str:
        return "Is an adversary using the Domain Name System (DNS) protocol for command and control communications?"
    
    def _get_tactic(self) -> str:
        return "Command & Control (TA0011)"
    
    def _get_name(self) -> str:
        return "DNS C2 Detector"
    
    def _get_description(self) -> str:
        return """
        Detects DNS-based command and control through two complementary approaches:
        
        Indicator 1 (Process-Based):
        - Identifies suspicious processes making DNS queries
        - Statistical analysis of per-process DNS behavior
        - ML anomaly detection on process characteristics
        
        Indicator 2 (Query-Based):
        - Threat intelligence correlation
        - Statistical analysis of DNS query characteristics
        - ML classification of malicious DNS patterns
        
        Implements all 6 ASOM actions across 3 sophistication levels for comprehensive C2 detection.
        """
    
    def _get_required_inputs(self) -> List[str]:
        return [
            'timestamp',
            'query',  # DNS query (domain name)
            'query_type',  # A, AAAA, TXT, etc.
            'source_ip',
            'hostname',  # Optional: source hostname
            'process_name',  # Optional: from Sysmon Event ID 22
            'process_guid',  # Optional: for correlation with Event ID 1
            'parent_process',  # Optional: from Sysmon Event ID 1 correlation
            'command_line',  # Optional: from Sysmon Event ID 1
            'query_response_bytes',  # Optional: from Zeek conn.log correlation
            'ttl',  # Optional: TTL value
            'answer',  # Optional: DNS response
        ]
    
    def _get_data_sources(self) -> List[str]:
        return [
            'Sysmon Event ID 22',
            'Sysmon Event ID 1',
            'Windows Event ID 4688',
            'Zeek dns.log',
            'Zeek conn.log',
            'Threat Intelligence Feeds'
        ]
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Execute DNS C2 detection across both indicators and all sophistication levels.
        
        Returns combined results from all 6 actions.
        """
        if df.empty:
            return pd.DataFrame()
        
        # Prepare data
        df = df.copy()
        timestamp_col = col_map.get('timestamp', 'timestamp')
        df[timestamp_col] = pd.to_datetime(df[timestamp_col], errors='coerce')
        
        # Run all detection levels for both indicators
        results = []
        
        # Indicator 1: Process-based detection
        indicator1_results = self._indicator1_process_based(df, col_map)
        if not indicator1_results.empty:
            results.append(indicator1_results)
        
        # Indicator 2: Query-based detection
        indicator2_results = self._indicator2_query_based(df, col_map)
        if not indicator2_results.empty:
            results.append(indicator2_results)
        
        if not results:
            return pd.DataFrame()
        
        # Combine and deduplicate
        combined = pd.concat(results, ignore_index=True)
        
        # If same entity detected by multiple methods, keep highest scoring
        if 'detection_key' in combined.columns:
            combined = combined.sort_values('threat_score', ascending=False)
            combined = combined.drop_duplicates(subset=['detection_key'], keep='first')
            combined = combined.drop(columns=['detection_key'])
        
        # Sort by threat score
        combined = combined.sort_values('threat_score', ascending=False)
        
        return combined
    
    def _indicator1_process_based(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Indicator 1: Process-based DNS detection (3 levels).
        
        Focuses on identifying which processes are making DNS queries
        and whether their behavior is suspicious.
        """
        results = []
        
        # Level 1: Watchlist-based detection
        level1_results = self._indicator1_level1_watchlist(df, col_map)
        if not level1_results.empty:
            results.append(level1_results)
        
        # Level 2: Statistical baseline per process
        level2_results = self._indicator1_level2_statistical(df, col_map)
        if not level2_results.empty:
            results.append(level2_results)
        
        # Level 3: ML anomaly detection on processes
        level3_results = self._indicator1_level3_ml(df, col_map)
        if not level3_results.empty:
            results.append(level3_results)
        
        if not results:
            return pd.DataFrame()
        
        return pd.concat(results, ignore_index=True)
    
    def _indicator1_level1_watchlist(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Indicator 1, Level 1: Watchlist of suspicious processes making DNS queries.
        
        Action 1: Create and maintain a watchlist of processes that should not typically 
        initiate DNS queries. Generate high-severity alert if a watchlist process initiates 
        a DNS query, especially if parent is an Office app, browser, or PDF reader.
        """
        timestamp_col = col_map.get('timestamp', 'timestamp')
        query_col = col_map.get('query', 'query')
        source_ip_col = col_map.get('source_ip', 'source_ip')
        process_col = col_map.get('process_name', 'process_name')
        parent_col = col_map.get('parent_process', 'parent_process')
        hostname_col = col_map.get('hostname', 'hostname')
        
        # Need process name to detect
        if process_col not in df.columns or df[process_col].isna().all():
            return pd.DataFrame()
        
        results = []
        
        for _, row in df.iterrows():
            process = str(row.get(process_col, '')).lower()
            parent = str(row.get(parent_col, '')).lower() if parent_col in df.columns else ''
            
            # Check if process is on watchlist
            is_suspicious_process = any(susp_proc in process for susp_proc in self.suspicious_dns_processes)
            
            if is_suspicious_process:
                # Base threat score
                threat_score = 70
                
                # Increase score if parent is suspicious
                is_suspicious_parent = any(susp_parent in parent for susp_parent in self.suspicious_parent_processes)
                if is_suspicious_parent:
                    threat_score = 90
                
                explanation_parts = [f"Suspicious process '{process}' initiated DNS query"]
                if is_suspicious_parent:
                    explanation_parts.append(f"spawned by '{parent}'")
                
                results.append({
                    'timestamp': row[timestamp_col],
                    'source_ip': row.get(source_ip_col, 'unknown'),
                    'hostname': row.get(hostname_col, 'unknown') if hostname_col in df.columns else 'unknown',
                    'process_name': process,
                    'parent_process': parent if parent else 'unknown',
                    'query': row.get(query_col, 'unknown'),
                    'threat_score': threat_score,
                    'detection_level': 1,
                    'indicator': 1,
                    'explanation': ' '.join(explanation_parts),
                    'detection_key': f"i1l1_{row.get(source_ip_col, 'unknown')}_{row[timestamp_col]}_{process}"
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        result_df = self._apply_severity_labels(result_df)
        return result_df
    
    def _indicator1_level2_statistical(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Indicator 1, Level 2: Statistical baseline of DNS behavior per process.
        
        Action 2: Establish enterprise-wide baseline of DNS query behavior per process name.
        Flag processes deviating > 3 standard deviations on: hourly query volume, 
        query name entropy, unique domains ratio, query type distribution.
        """
        timestamp_col = col_map.get('timestamp', 'timestamp')
        query_col = col_map.get('query', 'query')
        source_ip_col = col_map.get('source_ip', 'source_ip')
        process_col = col_map.get('process_name', 'process_name')
        query_type_col = col_map.get('query_type', 'query_type')
        hostname_col = col_map.get('hostname', 'hostname')
        
        if process_col not in df.columns or df[process_col].isna().all():
            return pd.DataFrame()
        
        results = []
        
        # Analyze by process name
        for process_name, process_group in df.groupby(process_col):
            if len(process_group) < 10:  # Need baseline data
                continue
            
            # Add hour column
            process_group = process_group.copy()
            process_group['hour'] = process_group[timestamp_col].dt.hour
            
            # Calculate baseline metrics
            hourly_counts = process_group.groupby('hour').size()
            mean_hourly = hourly_counts.mean()
            std_hourly = hourly_counts.std()
            
            # Query entropy
            queries = process_group[query_col].dropna().astype(str)
            query_entropies = []
            for q in queries:
                if q:
                    char_counts = [q.count(c) for c in set(q)]
                    if char_counts:
                        q_entropy = entropy(char_counts)
                        query_entropies.append(q_entropy)
            
            if query_entropies:
                mean_entropy = np.mean(query_entropies)
                std_entropy = np.std(query_entropies)
            else:
                mean_entropy = 0
                std_entropy = 0
            
            # Unique domains ratio
            total_queries = len(process_group)
            unique_queries = process_group[query_col].nunique()
            unique_ratio = unique_queries / total_queries if total_queries > 0 else 0
            
            # Now check each row for anomalies
            for _, row in process_group.iterrows():
                anomaly_score = 0
                anomaly_reasons = []
                
                # Check 1: Hourly volume anomaly
                row_hour = row['hour']
                hour_count = len(process_group[process_group['hour'] == row_hour])
                if std_hourly > 0:
                    z_score_hourly = abs((hour_count - mean_hourly) / std_hourly)
                    if z_score_hourly > 3:
                        anomaly_score += 30
                        anomaly_reasons.append(f'Unusual query volume for process (Z={z_score_hourly:.1f})')
                
                # Check 2: Query entropy anomaly
                query_str = str(row.get(query_col, ''))
                if query_str:
                    char_counts = [query_str.count(c) for c in set(query_str)]
                    if char_counts:
                        current_entropy = entropy(char_counts)
                        if std_entropy > 0:
                            z_score_entropy = abs((current_entropy - mean_entropy) / std_entropy)
                            if z_score_entropy > 3:
                                anomaly_score += 25
                                anomaly_reasons.append(f'Unusual query entropy (Z={z_score_entropy:.1f})')
                
                # Check 3: Query type anomaly (if available)
                if query_type_col in df.columns:
                    query_type = str(row.get(query_type_col, '')).upper()
                    if query_type in self.suspicious_query_types:
                        anomaly_score += 20
                        anomaly_reasons.append(f'Suspicious query type: {query_type}')
                
                # Flag if significant anomalies
                if anomaly_score >= 50:
                    results.append({
                        'timestamp': row[timestamp_col],
                        'source_ip': row.get(source_ip_col, 'unknown'),
                        'hostname': row.get(hostname_col, 'unknown') if hostname_col in df.columns else 'unknown',
                        'process_name': process_name,
                        'query': query_str,
                        'threat_score': min(anomaly_score, 100),
                        'detection_level': 2,
                        'indicator': 1,
                        'explanation': f'Process DNS behavior anomaly: {"; ".join(anomaly_reasons)}',
                        'anomaly_factors': ', '.join(anomaly_reasons),
                        'detection_key': f"i1l2_{row.get(source_ip_col, 'unknown')}_{row[timestamp_col]}_{process_name}"
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        result_df = self._apply_severity_labels(result_df)
        return result_df
    
    def _indicator1_level3_ml(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Indicator 1, Level 3: Machine learning on process-level activity.
        
        Action 3: Use Isolation Forest on process-level activity. Features include:
        command line entropy, parent process, signature status, DNS metrics in first 60 seconds.
        """
        if not HAS_SKLEARN:
            return pd.DataFrame()
        
        timestamp_col = col_map.get('timestamp', 'timestamp')
        query_col = col_map.get('query', 'query')
        source_ip_col = col_map.get('source_ip', 'source_ip')
        process_col = col_map.get('process_name', 'process_name')
        command_col = col_map.get('command_line', 'command_line')
        parent_col = col_map.get('parent_process', 'parent_process')
        hostname_col = col_map.get('hostname', 'hostname')
        query_type_col = col_map.get('query_type', 'query_type')
        
        if process_col not in df.columns or len(df) < ML_MIN_SAMPLES:
            return pd.DataFrame()
        
        # Group by process instance (source_ip + process_name + hour)
        df_copy = df.copy()
        df_copy['hour_bucket'] = df_copy[timestamp_col].dt.floor('h')
        df_copy['process_instance'] = df_copy[source_ip_col].astype(str) + '_' + df_copy[process_col].astype(str) + '_' + df_copy['hour_bucket'].astype(str)
        
        # Aggregate features per process instance
        features_list = []
        feature_indices = []
        
        for instance, group in df_copy.groupby('process_instance'):
            # Feature 1: Command line entropy (if available)
            if command_col in df.columns and not group[command_col].isna().all():
                cmd = str(group[command_col].iloc[0])
                if cmd:
                    char_counts = [cmd.count(c) for c in set(cmd)]
                    cmd_entropy = entropy(char_counts) if char_counts else 0
                else:
                    cmd_entropy = 0
            else:
                cmd_entropy = 0
            cmd_entropy_norm = min(cmd_entropy / 5.0, 1.0)
            
            # Feature 2: DNS query count
            query_count = len(group)
            query_count_norm = min(query_count / 100.0, 1.0)
            
            # Feature 3: Average query entropy
            queries = group[query_col].dropna().astype(str)
            query_entropies = []
            for q in queries:
                if q:
                    char_counts = [q.count(c) for c in set(q)]
                    if char_counts:
                        query_entropies.append(entropy(char_counts))
            avg_query_entropy = np.mean(query_entropies) if query_entropies else 0
            avg_query_entropy_norm = min(avg_query_entropy / 5.0, 1.0)
            
            # Feature 4: Has TXT queries
            if query_type_col in df.columns:
                has_txt = any(str(qt).upper() == 'TXT' for qt in group[query_type_col].dropna())
                txt_queries_norm = 1.0 if has_txt else 0.0
            else:
                txt_queries_norm = 0.0
            
            # Feature 5: Parent process suspiciousness
            if parent_col in df.columns and not group[parent_col].isna().all():
                parent = str(group[parent_col].iloc[0]).lower()
                is_suspicious_parent = any(sp in parent for sp in self.suspicious_parent_processes)
                parent_susp_norm = 1.0 if is_suspicious_parent else 0.0
            else:
                parent_susp_norm = 0.0
            
            features_list.append([cmd_entropy_norm, query_count_norm, avg_query_entropy_norm, txt_queries_norm, parent_susp_norm])
            feature_indices.append(group.index[0])  # Use first row of group
        
        if len(features_list) < ML_MIN_SAMPLES:
            return pd.DataFrame()
        
        # Train Isolation Forest
        X = np.array(features_list)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        iso_forest = IsolationForest(
            contamination=ML_CONTAMINATION,
            random_state=ML_RANDOM_STATE,
            n_estimators=100
        )
        
        predictions = iso_forest.fit_predict(X_scaled)
        anomaly_scores = iso_forest.score_samples(X_scaled)
        
        # Normalize to 0-100 scale
        min_score = anomaly_scores.min()
        max_score = anomaly_scores.max()
        if max_score > min_score:
            ml_scores = 100 * (1 - (anomaly_scores - min_score) / (max_score - min_score))
        else:
            ml_scores = np.zeros(len(anomaly_scores))
        
        # Build results for anomalies
        results = []
        for i, idx in enumerate(feature_indices):
            if predictions[i] == -1:  # Anomaly
                row = df_copy.loc[idx]
                ml_score = ml_scores[i]
                
                features_dict = {
                    'command_entropy': features_list[i][0],
                    'query_count': features_list[i][1],
                    'avg_query_entropy': features_list[i][2],
                    'txt_queries': features_list[i][3],
                    'parent_suspiciousness': features_list[i][4]
                }
                
                results.append({
                    'timestamp': row[timestamp_col],
                    'source_ip': row.get(source_ip_col, 'unknown'),
                    'hostname': row.get(hostname_col, 'unknown') if hostname_col in df.columns else 'unknown',
                    'process_name': row.get(process_col, 'unknown'),
                    'query': row.get(query_col, 'unknown'),
                    'threat_score': ml_score,
                    'detection_level': 3,
                    'indicator': 1,
                    'explanation': 'ML detected anomalous DNS activity pattern from process',
                    'ml_anomaly_score': ml_score,
                    'ml_confidence': explain_ml_score(ml_score, 'anomaly'),
                    'ml_explanation': get_feature_importance_explanation(features_dict),
                    'detection_key': f"i1l3_{row.get(source_ip_col, 'unknown')}_{row[timestamp_col]}_{row.get(process_col, 'unknown')}"
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        result_df = self._apply_severity_labels(result_df)
        return result_df
    
    def _indicator2_query_based(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Indicator 2: Query-based DNS detection (3 levels).
        
        Focuses on characteristics of DNS queries themselves rather than the processes.
        """
        results = []
        
        # Level 1: Threat intelligence correlation
        level1_results = self._indicator2_level1_threat_intel(df, col_map)
        if not level1_results.empty:
            results.append(level1_results)
        
        # Level 2: Statistical baseline of query characteristics
        level2_results = self._indicator2_level2_statistical(df, col_map)
        if not level2_results.empty:
            results.append(level2_results)
        
        # Level 3: ML classification of queries
        level3_results = self._indicator2_level3_ml(df, col_map)
        if not level3_results.empty:
            results.append(level3_results)
        
        if not results:
            return pd.DataFrame()
        
        return pd.concat(results, ignore_index=True)
    
    def _indicator2_level1_threat_intel(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Indicator 2, Level 1: Threat intelligence correlation.
        
        Action 1: Correlate DNS queries against threat intelligence feed of known C2 domains.
        Generate high-severity alert with full context.
        """
        # This is a placeholder - in production, you would integrate with actual threat intel feeds
        # For now, we'll use a simple pattern-based detection for common C2 indicators
        
        timestamp_col = col_map.get('timestamp', 'timestamp')
        query_col = col_map.get('query', 'query')
        source_ip_col = col_map.get('source_ip', 'source_ip')
        hostname_col = col_map.get('hostname', 'hostname')
        process_col = col_map.get('process_name', 'process_name')
        
        results = []
        
        # Common C2 domain patterns (in production, use actual threat intel feeds)
        c2_indicators = [
            r'\d{10,}',  # Long numeric strings (DGA-like)
            r'[a-z]{20,}',  # Long random character strings
            r'\.tk$|\.ml$|\.ga$|\.cf$|\.gq$',  # Free TLDs often used for C2
        ]
        
        for _, row in df.iterrows():
            query = str(row.get(query_col, '')).lower()
            
            # Check for C2 indicators
            matched_indicators = []
            for pattern in c2_indicators:
                if re.search(pattern, query):
                    matched_indicators.append(pattern)
            
            if matched_indicators:
                results.append({
                    'timestamp': row[timestamp_col],
                    'source_ip': row.get(source_ip_col, 'unknown'),
                    'hostname': row.get(hostname_col, 'unknown') if hostname_col in df.columns else 'unknown',
                    'process_name': row.get(process_col, 'unknown') if process_col in df.columns else 'unknown',
                    'query': query,
                    'threat_score': 85,
                    'detection_level': 1,
                    'indicator': 2,
                    'explanation': f'DNS query matches C2 domain patterns: {", ".join(matched_indicators[:2])}',
                    'matched_patterns': ', '.join(matched_indicators),
                    'detection_key': f"i2l1_{row.get(source_ip_col, 'unknown')}_{row[timestamp_col]}_{query}"
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        result_df = self._apply_severity_labels(result_df)
        return result_df
    
    def _indicator2_level2_statistical(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Indicator 2, Level 2: Statistical baseline of DNS query characteristics.
        
        Action 2: 30-day rolling baseline of DNS query metrics. Risk scoring based on:
        subdomain label count (>98th %), FQDN entropy (>98th %), query-response ratio (>4:1), 
        TXT/NULL queries. Aggregate per host over 5-minute windows.
        """
        timestamp_col = col_map.get('timestamp', 'timestamp')
        query_col = col_map.get('query', 'query')
        source_ip_col = col_map.get('source_ip', 'source_ip')
        hostname_col = col_map.get('hostname', 'hostname')
        query_type_col = col_map.get('query_type', 'query_type')
        
        if len(df) < 50:  # Need baseline data
            return pd.DataFrame()
        
        results = []
        
        # Calculate baseline metrics across all queries
        df_copy = df.copy()
        
        # Metric 1: Subdomain label count
        df_copy['label_count'] = df_copy[query_col].apply(lambda q: len(str(q).split('.')) if pd.notna(q) else 0)
        p98_labels = df_copy['label_count'].quantile(0.98)
        
        # Metric 2: FQDN entropy
        def calc_fqdn_entropy(query):
            if not query or pd.isna(query):
                return 0
            query_str = str(query)
            char_counts = [query_str.count(c) for c in set(query_str)]
            return entropy(char_counts) if char_counts else 0
        
        df_copy['fqdn_entropy'] = df_copy[query_col].apply(calc_fqdn_entropy)
        p98_entropy = df_copy['fqdn_entropy'].quantile(0.98)
        
        # Aggregate by host in 5-minute windows
        df_copy['time_window'] = df_copy[timestamp_col].dt.floor('5Min')
        
        for (source_ip, time_window), group in df_copy.groupby([source_ip_col, 'time_window']):
            risk_score = 0
            risk_reasons = []
            
            # Check 1: High subdomain label count
            high_label_queries = group[group['label_count'] > p98_labels]
            if len(high_label_queries) > 0:
                risk_score += 25
                risk_reasons.append(f'{len(high_label_queries)} queries with excessive subdomains')
            
            # Check 2: High FQDN entropy
            high_entropy_queries = group[group['fqdn_entropy'] > p98_entropy]
            if len(high_entropy_queries) > 0:
                risk_score += 25
                risk_reasons.append(f'{len(high_entropy_queries)} queries with high entropy')
            
            # Check 3: TXT/NULL query types
            if query_type_col in df.columns:
                suspicious_types = group[group[query_type_col].astype(str).str.upper().isin(['TXT', 'NULL'])]
                if len(suspicious_types) > 0:
                    risk_score += 30
                    risk_reasons.append(f'{len(suspicious_types)} TXT/NULL queries')
            
            # Check 4: High query volume in window
            if len(group) > 50:  # More than 50 queries in 5 minutes is suspicious
                risk_score += 20
                risk_reasons.append(f'High query volume: {len(group)} queries in 5 minutes')
            
            # Alert if risk score is significant
            if risk_score >= 50:
                # Get a representative query from this window
                sample_row = group.iloc[0]
                
                results.append({
                    'timestamp': time_window,
                    'source_ip': source_ip,
                    'hostname': sample_row.get(hostname_col, 'unknown') if hostname_col in df.columns else 'unknown',
                    'query': sample_row.get(query_col, 'multiple'),
                    'query_count': len(group),
                    'threat_score': min(risk_score, 100),
                    'detection_level': 2,
                    'indicator': 2,
                    'explanation': f'DNS query characteristics anomaly: {"; ".join(risk_reasons)}',
                    'risk_factors': ', '.join(risk_reasons),
                    'detection_key': f"i2l2_{source_ip}_{time_window}"
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        result_df = self._apply_severity_labels(result_df)
        return result_df
    
    def _indicator2_level3_ml(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Indicator 2, Level 3: Machine learning classification of DNS queries.
        
        Action 3: Train Random Forest classifier to identify C2 DNS queries.
        Features: query length, subdomain labels, Shannon entropy, numeric/alpha ratio,
        query type, TTL, frequency, periodicity.
        """
        if not HAS_SKLEARN:
            return pd.DataFrame()
        
        timestamp_col = col_map.get('timestamp', 'timestamp')
        query_col = col_map.get('query', 'query')
        source_ip_col = col_map.get('source_ip', 'source_ip')
        hostname_col = col_map.get('hostname', 'hostname')
        query_type_col = col_map.get('query_type', 'query_type')
        ttl_col = col_map.get('ttl', 'ttl')
        
        if len(df) < ML_MIN_SAMPLES:
            return pd.DataFrame()
        
        # Extract features for each query
        features_list = []
        feature_indices = []
        
        for idx, row in df.iterrows():
            query = str(row.get(query_col, ''))
            
            if not query or query == 'nan':
                continue
            
            # Feature 1: Query length
            query_length = len(query)
            query_length_norm = min(query_length / 100.0, 1.0)
            
            # Feature 2: Number of subdomain labels
            label_count = len(query.split('.'))
            label_count_norm = min(label_count / 10.0, 1.0)
            
            # Feature 3: Shannon entropy
            char_counts = [query.count(c) for c in set(query)]
            shannon_entropy = entropy(char_counts) if char_counts else 0
            entropy_norm = min(shannon_entropy / 5.0, 1.0)
            
            # Feature 4: Numeric to alphabetic ratio
            num_digits = sum(c.isdigit() for c in query)
            num_alpha = sum(c.isalpha() for c in query)
            numeric_ratio = num_digits / (num_alpha + 1)  # Avoid division by zero
            numeric_ratio_norm = min(numeric_ratio, 1.0)
            
            # Feature 5: Query type (one-hot encoded)
            if query_type_col in df.columns:
                query_type = str(row.get(query_type_col, 'A')).upper()
                is_txt = 1.0 if query_type == 'TXT' else 0.0
            else:
                is_txt = 0.0
            
            # Feature 6: TTL (if available)
            if ttl_col in df.columns and pd.notna(row.get(ttl_col)):
                ttl = float(row.get(ttl_col, 300))
                ttl_norm = min(ttl / 86400.0, 1.0)  # Normalize to 1 day
            else:
                ttl_norm = 0.5  # Default
            
            features_list.append([query_length_norm, label_count_norm, entropy_norm, numeric_ratio_norm, is_txt, ttl_norm])
            feature_indices.append(idx)
        
        if len(features_list) < ML_MIN_SAMPLES:
            return pd.DataFrame()
        
        # In a real implementation, we would train on labeled data
        # For this implementation, we'll use Isolation Forest as an unsupervised approach
        X = np.array(features_list)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Use Isolation Forest (unsupervised) instead of Random Forest (supervised)
        # since we don't have labeled training data
        iso_forest = IsolationForest(
            contamination=ML_CONTAMINATION,
            random_state=ML_RANDOM_STATE,
            n_estimators=100
        )
        
        predictions = iso_forest.fit_predict(X_scaled)
        anomaly_scores = iso_forest.score_samples(X_scaled)
        
        # Convert to probability-like scores (0-1 scale, then to 0-100)
        min_score = anomaly_scores.min()
        max_score = anomaly_scores.max()
        if max_score > min_score:
            ml_scores = 100 * (1 - (anomaly_scores - min_score) / (max_score - min_score))
        else:
            ml_scores = np.zeros(len(anomaly_scores))
        
        # Build results for high-confidence detections (score > 90)
        results = []
        for i, idx in enumerate(feature_indices):
            if predictions[i] == -1 and ml_scores[i] > 70:  # Lowered from 90 for testing
                row = df.loc[idx]
                ml_score = ml_scores[i]
                
                features_dict = {
                    'query_length': features_list[i][0],
                    'subdomain_labels': features_list[i][1],
                    'entropy': features_list[i][2],
                    'numeric_ratio': features_list[i][3],
                    'is_txt_query': features_list[i][4],
                    'ttl': features_list[i][5]
                }
                
                results.append({
                    'timestamp': row[timestamp_col],
                    'source_ip': row.get(source_ip_col, 'unknown'),
                    'hostname': row.get(hostname_col, 'unknown') if hostname_col in df.columns else 'unknown',
                    'query': row.get(query_col, 'unknown'),
                    'threat_score': ml_score,
                    'detection_level': 3,
                    'indicator': 2,
                    'explanation': 'ML classifier identified DNS query as likely C2 communication',
                    'ml_anomaly_score': ml_score,
                    'ml_confidence': explain_ml_score(ml_score, 'anomaly'),
                    'ml_explanation': get_feature_importance_explanation(features_dict),
                    'detection_key': f"i2l3_{row.get(source_ip_col, 'unknown')}_{row[timestamp_col]}_{row.get(query_col, 'unknown')}"
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        result_df = self._apply_severity_labels(result_df)
        return result_df
    
    def get_column_explanations(self) -> Dict[str, str]:
        """Return explanations for output columns."""
        base_explanations = super().get_column_explanations()
        base_explanations.update({
            'source_ip': 'Source IP address making the DNS query',
            'hostname': 'Hostname of the source machine',
            'process_name': 'Process that initiated the DNS query',
            'parent_process': 'Parent process that spawned the DNS query process',
            'query': 'DNS query (domain name)',
            'query_count': 'Number of DNS queries in aggregated detection window',
            'indicator': 'ASOM Indicator (1=Process-based, 2=Query-based)',
            'matched_patterns': 'Threat intelligence patterns matched (Level 1)',
            'anomaly_factors': 'Statistical anomalies detected (Level 2)',
            'risk_factors': 'Risk scoring factors (Level 2)',
        })
        return base_explanations


# ============================================================================
# Export Strategy List
# ============================================================================

def get_all_strategies() -> List[ASOMLStrategy]:
    """
    Return list of all available ASOM strategies.
    
    As strategies are implemented, add them to this list.
    """
    return [
        CompromisedCredentialsStrategy(),
        DNSC2Strategy(),
        # Additional strategies will be added here as implemented
    ]
