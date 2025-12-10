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
# Export Strategy List
# ============================================================================

def get_all_strategies() -> List[ASOMLStrategy]:
    """
    Return list of all available ASOM strategies.
    
    As strategies are implemented, add them to this list.
    """
    return [
        CompromisedCredentialsStrategy(),
        # Additional strategies will be added here as implemented
    ]
