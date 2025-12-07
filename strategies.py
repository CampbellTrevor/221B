"""
strategies.py - Pure Python analytic logic for 221B threat hunting.

This module contains the abstract base class and concrete implementations
for various threat hunting strategies. No UI or database code is included.
"""

from abc import ABC, abstractmethod
import pandas as pd
import numpy as np
import re
from scipy.stats import entropy
from multiprocessing import Pool
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from collections import Counter

# Try to import plotly for visualizations (optional)
try:
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False

# Try to import scikit-learn for ML features (optional)
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import KMeans
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


# ML Configuration Constants
ML_MIN_SAMPLES = 50  # Minimum samples required to apply ML
ML_CONTAMINATION = 0.1  # Expected proportion of outliers (10%)
ML_RANDOM_STATE = 42  # For reproducible results


def explain_ml_score(score: float, method: str = "anomaly") -> str:
    """
    Generate plain-English explanation of ML score for analysts.
    
    Args:
        score: ML-generated score (typically 0-100 or -1 to 1)
        method: Type of ML method ('anomaly', 'cluster', 'outlier')
    
    Returns:
        Human-readable explanation string
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
        features: Dictionary of feature names to normalized values
    
    Returns:
        Explanation of top contributing features
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


class HuntStrategy(ABC):
    """
    Abstract base class for threat hunting strategies.
    
    Each strategy defines:
    - name: Human-readable name of the hunt
    - required_inputs: List of column names needed for analysis
    - analyze: Method that performs the analysis on a DataFrame
    """
    
    def __init__(self):
        self.name = self._get_name()
        self.required_inputs = self._get_required_inputs()
    
    @abstractmethod
    def _get_name(self) -> str:
        """Return the name of this hunting strategy."""
        pass
    
    @abstractmethod
    def _get_required_inputs(self) -> list:
        """Return the list of required input column names."""
        pass
    
    @abstractmethod
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Perform the threat hunting analysis.
        
        Args:
            df: Input DataFrame with raw data
            col_map: Dictionary mapping required_inputs to actual column names
                    e.g., {'timestamp': 'conn_ts', 'source_ip': 'id.orig_h'}
        
        Returns:
            DataFrame with analysis results
        """
        pass
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """
        Generate interactive visualizations for analysis results.
        
        Args:
            result_df: DataFrame with analysis results
            col_map: Optional column mapping used in analysis
        
        Returns:
            Plotly figure object or None if plotly not available
        """
        # Default implementation - can be overridden by subclasses
        if not HAS_PLOTLY:
            return None
        return None
    
    def get_column_explanations(self) -> dict:
        """
        Get explanations for output columns to help junior analysts.
        
        Returns:
            Dictionary mapping column names to plain-language explanations
        """
        # Default implementation - should be overridden by subclasses
        return {}
    
    def parallel_analyze(self, df: pd.DataFrame, col_map: dict, num_cores: int = 4) -> pd.DataFrame:
        """
        Optional parallel implementation of analysis using multiprocessing.
        
        Subclasses can override this method to provide optimized parallel processing.
        If not overridden, this will fall back to the standard analyze method.
        
        Args:
            df: Input DataFrame with raw data
            col_map: Dictionary mapping required_inputs to actual column names
            num_cores: Number of CPU cores to use for parallel processing
        
        Returns:
            DataFrame with analysis results
        """
        # Default implementation - just call the standard analyze method
        return self.analyze(df, col_map)


class BeaconStrategy(HuntStrategy):
    """
    Beacon Hunter - Detects C2 callbacks by analyzing time patterns.
    
    Calculates variance of time deltas between connections for each
    source/destination pair to identify rhythmic machine-like traffic.
    """
    
    # Minimum connections required for beacon detection
    MIN_CONNECTIONS = 5
    # Minimum beacon score to be considered suspicious
    MIN_BEACON_SCORE = 50
    
    def _get_name(self) -> str:
        return "Beacon Hunter (C2 Detection)"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'dest_ip']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze connection patterns to detect beaconing behavior.
        
        Uses a hybrid approach:
        1. Rule-based scoring (traditional logic)
        2. ML-based anomaly detection (Isolation Forest) when sufficient data
        
        Args:
            df: DataFrame with connection logs
            col_map: Mapping of {'timestamp': actual_col, 'source_ip': actual_col, 
                                  'dest_ip': actual_col}
        
        Returns:
            DataFrame with source_ip, dest_ip, connection_count, delta_variance, and beacon_score
            Plus ML columns: ml_anomaly_score, ml_confidence, ml_explanation
        """
        # Map columns
        ts_col = col_map['timestamp']
        src_col = col_map['source_ip']
        dst_col = col_map['dest_ip']
        
        # Ensure timestamp is datetime
        df = df.copy()
        df[ts_col] = pd.to_datetime(df[ts_col])
        
        # Sort by source, dest, and timestamp
        df = df.sort_values([src_col, dst_col, ts_col])
        
        # Group by source/dest pair
        results = []
        for (src_ip, dst_ip), group in df.groupby([src_col, dst_col]):
            # Require minimum connections for statistical significance
            if len(group) < self.MIN_CONNECTIONS:
                continue
            
            # Calculate time deltas in seconds
            timestamps = group[ts_col].values
            deltas = np.diff(timestamps).astype('timedelta64[s]').astype(float)
            
            if len(deltas) > 0:
                variance = np.var(deltas)
                mean_delta = np.mean(deltas)
                std_delta = np.std(deltas)
                
                # Calculate coefficient of variation (CV) - normalized measure of dispersion
                # Lower CV = more consistent timing = more suspicious
                cv = (std_delta / mean_delta) if mean_delta > 0 else float('inf')
                
                # Calculate beacon score (0-100, higher = more suspicious)
                # Based on: low variance, consistent timing, sufficient connections
                beacon_score = 0
                if cv < 0.1:  # Very consistent timing
                    beacon_score += 50
                elif cv < 0.3:  # Moderately consistent
                    beacon_score += 30
                elif cv < 0.5:  # Somewhat consistent
                    beacon_score += 15
                
                # Bonus for many connections
                if len(group) >= 20:
                    beacon_score += 30
                elif len(group) >= 10:
                    beacon_score += 20
                elif len(group) >= 5:
                    beacon_score += 10
                
                # Bonus for reasonable beacon intervals (1 min to 1 hour)
                if 60 <= mean_delta <= 3600:
                    beacon_score += 20
                
                results.append({
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'connection_count': len(group),
                    'delta_variance': variance,
                    'mean_delta_sec': mean_delta,
                    'coeff_variation': cv,
                    'beacon_score': min(beacon_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        
        # Apply ML-based anomaly detection if we have enough data and sklearn is available
        if not result_df.empty and HAS_SKLEARN and len(result_df) >= ML_MIN_SAMPLES:
            result_df = self._apply_ml_anomaly_detection(result_df)
        else:
            # Add placeholder ML columns when ML is not applied
            result_df['ml_anomaly_score'] = 0.0
            result_df['ml_confidence'] = 'N/A (insufficient data or sklearn not available)'
            result_df['ml_explanation'] = 'Rule-based detection only - need 50+ beaconing pairs for ML analysis'
        
        # Filter and sort by beacon score
        if not result_df.empty:
            # Only show high-confidence beacons
            result_df = result_df[result_df['beacon_score'] >= self.MIN_BEACON_SCORE]
            result_df = result_df.sort_values('beacon_score', ascending=False)
        
        return result_df
    
    def _apply_ml_anomaly_detection(self, result_df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply Isolation Forest ML model to detect anomalous beaconing patterns.
        
        This method is called when sufficient data is available (50+ samples).
        It uses timing features to identify unusual beaconing behavior that might
        indicate C2 communication versus legitimate periodic traffic.
        
        Args:
            result_df: DataFrame with rule-based beacon analysis results
        
        Returns:
            DataFrame with additional ML columns: ml_anomaly_score, ml_confidence, ml_explanation
        """
        # Feature engineering: Select features for ML model
        # We use timing characteristics that distinguish C2 beaconing from normal periodic traffic
        ml_features = ['coeff_variation', 'mean_delta_sec', 'connection_count', 'delta_variance']
        
        # Prepare feature matrix
        X = result_df[ml_features].copy()
        
        # Handle infinite values (can occur with cv when mean_delta is 0)
        X = X.replace([np.inf, -np.inf], np.nan)
        X = X.fillna(X.median())
        
        # Scale features (important for distance-based algorithms like Isolation Forest)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Train Isolation Forest model
        # contamination=0.1 means we expect ~10% of data to be anomalies (beacons)
        # n_estimators=100 for stable predictions
        # random_state for reproducibility
        iso_forest = IsolationForest(
            contamination=ML_CONTAMINATION,
            n_estimators=100,
            random_state=ML_RANDOM_STATE,
            n_jobs=-1  # Use all CPU cores
        )
        
        # Fit and predict
        iso_forest.fit(X_scaled)
        
        # Get anomaly predictions (-1 = anomaly, 1 = normal)
        predictions = iso_forest.predict(X_scaled)
        
        # Get anomaly scores (lower = more anomalous)
        # decision_function returns negative scores for anomalies
        anomaly_scores_raw = iso_forest.decision_function(X_scaled)
        
        # Convert to 0-100 scale where higher = more anomalous
        # Normalize using percentile ranking
        from scipy.stats import rankdata
        ml_anomaly_score = (rankdata(anomaly_scores_raw) / len(anomaly_scores_raw)) * 100
        
        # Add ML results to dataframe
        result_df['ml_anomaly_score'] = ml_anomaly_score
        result_df['ml_prediction'] = predictions
        
        # Generate confidence and explanation for each detection
        ml_confidence_list = []
        ml_explanation_list = []
        
        for idx, row in result_df.iterrows():
            score = row['ml_anomaly_score']
            is_anomaly = row['ml_prediction'] == -1
            
            # Confidence level based on score
            if is_anomaly and score >= 75:
                confidence = "HIGH"
                explanation = "🔴 ML HIGH CONFIDENCE: This beaconing pattern is highly unusual. Features like timing consistency and connection frequency are outliers compared to other traffic."
            elif is_anomaly and score >= 50:
                confidence = "MEDIUM"
                explanation = "🟡 ML MEDIUM CONFIDENCE: Moderate anomaly detected. Some timing characteristics differ from normal patterns, worth investigating."
            elif is_anomaly:
                confidence = "LOW"
                explanation = "🟢 ML LOW CONFIDENCE: Slight anomaly detected but similar to other patterns. Rule-based detection is primary indicator."
            else:
                confidence = "NORMAL"
                explanation = f"ℹ️ ML sees this as normal periodic traffic (score: {score:.1f}/100). Rule-based logic flagged it due to timing regularity."
            
            # Add feature contribution explanation
            feature_vals = {
                'timing_consistency': 1.0 - row['coeff_variation'],  # Lower CV = more consistent
                'connection_frequency': min(row['connection_count'] / 50.0, 1.0),  # Normalize to 0-1
                'interval_regularity': 1.0 if 60 <= row['mean_delta_sec'] <= 3600 else 0.5
            }
            
            feature_explanation = get_feature_importance_explanation(feature_vals)
            explanation += f" {feature_explanation}"
            
            ml_confidence_list.append(confidence)
            ml_explanation_list.append(explanation)
        
        result_df['ml_confidence'] = ml_confidence_list
        result_df['ml_explanation'] = ml_explanation_list
        
        # Drop the internal ml_prediction column (not needed in output)
        result_df = result_df.drop(columns=['ml_prediction'])
        
        return result_df
    
    @staticmethod
    def _process_beacon_group(group_data):
        """
        Process a single source/dest group for beacon detection.
        
        This static method is used for parallel processing.
        
        Args:
            group_data: Tuple of ((src_ip, dst_ip), group_df, ts_col, min_connections)
        
        Returns:
            Dictionary with analysis results or None if group doesn't meet criteria
        """
        (src_ip, dst_ip), group, ts_col, min_connections = group_data
        
        # Require minimum connections for statistical significance
        if len(group) < min_connections:
            return None
        
        # Calculate time deltas in seconds
        timestamps = group[ts_col].values
        deltas = np.diff(timestamps).astype('timedelta64[s]').astype(float)
        
        if len(deltas) == 0:
            return None
        
        variance = np.var(deltas)
        mean_delta = np.mean(deltas)
        std_delta = np.std(deltas)
        
        # Calculate coefficient of variation (CV)
        cv = (std_delta / mean_delta) if mean_delta > 0 else float('inf')
        
        # Calculate beacon score (0-100, higher = more suspicious)
        beacon_score = 0
        if cv < 0.1:
            beacon_score += 50
        elif cv < 0.3:
            beacon_score += 30
        elif cv < 0.5:
            beacon_score += 15
        
        # Bonus for many connections
        if len(group) >= 20:
            beacon_score += 30
        elif len(group) >= 10:
            beacon_score += 20
        elif len(group) >= 5:
            beacon_score += 10
        
        # Bonus for reasonable beacon intervals (1 min to 1 hour)
        if 60 <= mean_delta <= 3600:
            beacon_score += 20
        
        return {
            'source_ip': src_ip,
            'dest_ip': dst_ip,
            'connection_count': len(group),
            'delta_variance': variance,
            'mean_delta_sec': mean_delta,
            'coeff_variation': cv,
            'beacon_score': min(beacon_score, 100)
        }
    
    def parallel_analyze(self, df: pd.DataFrame, col_map: dict, num_cores: int = 4) -> pd.DataFrame:
        """
        Parallel implementation of beacon detection analysis.
        
        Args:
            df: DataFrame with connection logs
            col_map: Mapping of column names
            num_cores: Number of CPU cores to use
        
        Returns:
            DataFrame with analysis results
        """
        # Map columns
        ts_col = col_map['timestamp']
        src_col = col_map['source_ip']
        dst_col = col_map['dest_ip']
        
        # Ensure timestamp is datetime
        df = df.copy()
        df[ts_col] = pd.to_datetime(df[ts_col])
        
        # Sort by source, dest, and timestamp
        df = df.sort_values([src_col, dst_col, ts_col])
        
        # Prepare groups for parallel processing
        groups = [(key, group, ts_col, self.MIN_CONNECTIONS) 
                  for key, group in df.groupby([src_col, dst_col])]
        
        # Process groups in parallel
        # Try multiprocessing first, fall back to threading if it fails
        # (Threading is more compatible with Jupyter notebooks)
        try:
            with Pool(processes=num_cores) as pool:
                results = pool.map(self._process_beacon_group, groups)
        except Exception:
            # Fall back to threading for Jupyter notebook compatibility
            with ThreadPoolExecutor(max_workers=num_cores) as executor:
                results = list(executor.map(self._process_beacon_group, groups))
        
        # Filter out None results
        results = [r for r in results if r is not None]
        
        result_df = pd.DataFrame(results)
        
        # Filter and sort by beacon score
        if not result_df.empty:
            result_df = result_df[result_df['beacon_score'] >= self.MIN_BEACON_SCORE]
            result_df = result_df.sort_values('beacon_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate beacon detection visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Create scatter plot: beacon score vs connection count
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['connection_count'],
            y=result_df['beacon_score'],
            mode='markers',
            marker=dict(
                size=10,
                color=result_df['beacon_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Beacon<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Dest: {result_df.iloc[i]['dest_ip']}<br>Score: {result_df.iloc[i]['beacon_score']:.0f}<br>Connections: {result_df.iloc[i]['connection_count']}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Beacon Detection: Score vs Connection Count",
            xaxis_title="Connection Count",
            yaxis_title="Beacon Score (0-100)",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for BeaconStrategy output columns."""
        return {
            'source_ip': 'The IP address that initiated the connections',
            'dest_ip': 'The destination IP address being contacted',
            'connection_count': 'Total number of connections observed between this source and destination',
            'delta_variance': 'How much the timing between connections varies (lower = more consistent)',
            'mean_delta_sec': 'Average time (in seconds) between consecutive connections',
            'coeff_variation': 'Normalized measure of timing consistency (lower = more regular/suspicious). Values below 0.3 indicate very consistent timing patterns typical of automated C2 beaconing',
            'beacon_score': 'Overall suspiciousness score (0-100). Higher scores indicate stronger evidence of C2 beaconing. Scores ≥50 suggest automated beaconing behavior worth investigating',
            'ml_anomaly_score': '🤖 MACHINE LEARNING: How unusual this beaconing pattern is compared to all others (0-100). Higher scores mean ML identified this as more anomalous. Requires 50+ beaconing pairs for ML analysis',
            'ml_confidence': '🤖 ML CONFIDENCE LEVEL: How confident the machine learning model is about this detection (HIGH/MEDIUM/LOW/NORMAL). Shows whether ML agrees with rule-based detection',
            'ml_explanation': '🤖 ML REASONING: Plain English explanation of why machine learning flagged this, including which features (timing consistency, connection frequency, interval regularity) contributed most to the detection'
        }


class EntropyStrategy(HuntStrategy):
    """
    Entropy Analyzer - Detects DNS tunneling and DGA domains.
    
    Calculates Shannon Entropy on string fields to identify
    high-entropy, long strings indicative of data exfiltration.
    """
    
    # Minimum suspicion score to be considered high-risk
    MIN_SUSPICION_SCORE = 50
    # Batches per core for parallel processing (more batches = better load distribution)
    BATCHES_PER_CORE = 4
    
    def _get_name(self) -> str:
        return "Entropy Analyzer (DNS Tunneling)"
    
    def _get_required_inputs(self) -> list:
        return ['target_string']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Calculate Shannon Entropy for string fields.
        
        Uses a hybrid approach:
        1. Rule-based scoring (entropy + length thresholds)
        2. ML-based clustering (KMeans) to group similar DGA/tunneling patterns
        
        Args:
            df: DataFrame with string data (e.g., DNS queries)
            col_map: Mapping of {'target_string': actual_col}
        
        Returns:
            DataFrame with target_string, string_length, entropy_score, and suspicion_score
            Plus ML columns: ml_cluster, ml_cluster_risk, ml_explanation
        """
        # Map columns
        str_col = col_map['target_string']
        
        # Calculate entropy for each string
        df = df.copy()
        df = df.dropna(subset=[str_col])
        
        def calculate_shannon_entropy(text: str) -> float:
            """Calculate Shannon Entropy for a string."""
            if not text:
                return 0.0
            
            # Count character frequencies
            char_counts = {}
            for char in text:
                char_counts[char] = char_counts.get(char, 0) + 1
            
            # Calculate probabilities
            length = len(text)
            probabilities = [count / length for count in char_counts.values()]
            
            # Calculate entropy
            return entropy(probabilities, base=2)
        
        df['entropy_score'] = df[str_col].apply(calculate_shannon_entropy)
        df['string_length'] = df[str_col].str.len()
        
        # Calculate suspicion score (0-100) based on entropy and length
        # High entropy + long length = more suspicious
        df['suspicion_score'] = 0.0
        
        # Entropy scoring (0-50 points)
        # High entropy (> 4.5) is suspicious for domains/DNS
        df.loc[df['entropy_score'] >= 4.5, 'suspicion_score'] += 50
        df.loc[(df['entropy_score'] >= 4.0) & (df['entropy_score'] < 4.5), 'suspicion_score'] += 35
        df.loc[(df['entropy_score'] >= 3.5) & (df['entropy_score'] < 4.0), 'suspicion_score'] += 20
        
        # Length scoring (0-50 points)
        # Very long strings are suspicious (potential data exfil)
        df.loc[df['string_length'] >= 50, 'suspicion_score'] += 50
        df.loc[(df['string_length'] >= 30) & (df['string_length'] < 50), 'suspicion_score'] += 35
        df.loc[(df['string_length'] >= 20) & (df['string_length'] < 30), 'suspicion_score'] += 20
        
        # Create result DataFrame
        result_df = df[[str_col, 'string_length', 'entropy_score', 'suspicion_score']].copy()
        result_df = result_df.rename(columns={str_col: 'target_string'})
        
        # Filter to high-suspicion items only
        result_df = result_df[result_df['suspicion_score'] >= self.MIN_SUSPICION_SCORE]
        
        # Apply ML clustering if we have enough data
        if not result_df.empty and HAS_SKLEARN and len(result_df) >= ML_MIN_SAMPLES:
            result_df = self._apply_ml_clustering(result_df)
        else:
            # Add placeholder ML columns
            result_df['ml_cluster'] = 'N/A'
            result_df['ml_cluster_risk'] = 'N/A'
            result_df['ml_explanation'] = 'Rule-based detection only - need 50+ suspicious strings for ML clustering'
        
        # Sort by suspicion score (descending)
        result_df = result_df.sort_values('suspicion_score', ascending=False)
        
        # Remove duplicates (aggregate counts if present)
        result_df = result_df.drop_duplicates(subset=['target_string'], keep='first')
        
        return result_df
    
    def _apply_ml_clustering(self, result_df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply KMeans clustering to group similar DGA/tunneling patterns.
        
        This helps analysts understand if multiple suspicious domains follow
        the same generation pattern (likely same malware family) or if they're
        isolated incidents.
        
        Args:
            result_df: DataFrame with rule-based entropy analysis results
        
        Returns:
            DataFrame with additional ML columns: ml_cluster, ml_cluster_risk, ml_explanation
        """
        # Feature engineering for clustering
        ml_features = ['entropy_score', 'string_length']
        X = result_df[ml_features].copy()
        
        # Scale features for clustering
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Determine optimal number of clusters (3-5 clusters typical for DGA patterns)
        # Use elbow method implicitly: min(n_samples//10, 5)
        n_clusters = min(max(len(result_df) // 10, 3), 5)
        
        # Train KMeans model
        kmeans = KMeans(
            n_clusters=n_clusters,
            random_state=ML_RANDOM_STATE,
            n_init=10
        )
        
        # Fit and predict clusters
        cluster_labels = kmeans.fit_predict(X_scaled)
        result_df['ml_cluster'] = cluster_labels
        
        # Calculate cluster risk levels based on average suspicion scores
        cluster_stats = result_df.groupby('ml_cluster').agg({
            'suspicion_score': ['mean', 'count'],
            'entropy_score': 'mean',
            'string_length': 'mean'
        }).round(2)
        
        # Assign risk levels to clusters
        cluster_risk_map = {}
        cluster_descriptions = {}
        
        for cluster_id in range(n_clusters):
            if cluster_id not in cluster_stats.index:
                continue
                
            avg_suspicion = cluster_stats.loc[cluster_id, ('suspicion_score', 'mean')]
            cluster_size = cluster_stats.loc[cluster_id, ('suspicion_score', 'count')]
            avg_entropy = cluster_stats.loc[cluster_id, ('entropy_score', 'mean')]
            avg_length = cluster_stats.loc[cluster_id, ('string_length', 'mean')]
            
            # Determine risk level
            if avg_suspicion >= 75:
                risk_level = "🔴 CRITICAL"
                risk_desc = f"High-risk DGA pattern cluster (avg score: {avg_suspicion:.1f})"
            elif avg_suspicion >= 60:
                risk_level = "🟠 HIGH"
                risk_desc = f"Suspicious pattern cluster (avg score: {avg_suspicion:.1f})"
            else:
                risk_level = "🟡 MEDIUM"
                risk_desc = f"Moderate pattern cluster (avg score: {avg_suspicion:.1f})"
            
            cluster_risk_map[cluster_id] = risk_level
            
            # Create detailed description
            pattern_type = ""
            if avg_entropy >= 4.5 and avg_length >= 40:
                pattern_type = "Long, high-entropy strings (likely DNS tunneling or data exfil)"
            elif avg_entropy >= 4.5:
                pattern_type = "High randomness (DGA domains or encoded data)"
            elif avg_length >= 40:
                pattern_type = "Long subdomains (potential DNS tunneling)"
            else:
                pattern_type = "Moderate entropy and length"
            
            cluster_descriptions[cluster_id] = (
                f"🤖 ML CLUSTER {cluster_id}: {risk_desc}. "
                f"Contains {int(cluster_size)} similar strings. "
                f"Pattern: {pattern_type}. "
                f"Avg entropy: {avg_entropy:.2f}, avg length: {int(avg_length)} chars. "
                f"This cluster likely represents {'the same malware family or attack' if cluster_size > 5 else 'similar suspicious activity'}."
            )
        
        # Map risk levels and explanations to results
        result_df['ml_cluster_risk'] = result_df['ml_cluster'].map(cluster_risk_map)
        result_df['ml_explanation'] = result_df['ml_cluster'].map(cluster_descriptions)
        
        return result_df
    
    @staticmethod
    def _process_entropy_batch(batch_data):
        """
        Process a batch of strings for entropy calculation.
        
        This static method is used for parallel processing.
        
        Args:
            batch_data: Tuple of (strings_list, min_suspicion_score)
        
        Returns:
            List of dictionaries with analysis results
        """
        strings_list, min_suspicion_score = batch_data
        results = []
        
        for text in strings_list:
            if not text or not isinstance(text, str):
                continue
            
            # Calculate Shannon Entropy
            char_counts = {}
            for char in text:
                char_counts[char] = char_counts.get(char, 0) + 1
            
            length = len(text)
            probabilities = [count / length for count in char_counts.values()]
            ent_score = entropy(probabilities, base=2)
            
            # Calculate suspicion score
            suspicion = 0.0
            
            # Entropy scoring (0-50 points)
            if ent_score >= 4.5:
                suspicion += 50
            elif ent_score >= 4.0:
                suspicion += 35
            elif ent_score >= 3.5:
                suspicion += 20
            
            # Length scoring (0-50 points)
            if length >= 50:
                suspicion += 50
            elif length >= 30:
                suspicion += 35
            elif length >= 20:
                suspicion += 20
            
            # Only include if meets minimum threshold
            if suspicion >= min_suspicion_score:
                results.append({
                    'target_string': text,
                    'string_length': length,
                    'entropy_score': ent_score,
                    'suspicion_score': suspicion
                })
        
        return results
    
    def parallel_analyze(self, df: pd.DataFrame, col_map: dict, num_cores: int = 4) -> pd.DataFrame:
        """
        Parallel implementation of entropy analysis.
        
        Args:
            df: DataFrame with string data
            col_map: Mapping of column names
            num_cores: Number of CPU cores to use
        
        Returns:
            DataFrame with analysis results
        """
        # Map columns
        str_col = col_map['target_string']
        
        # Get unique strings to analyze
        df = df.copy()
        df = df.dropna(subset=[str_col])
        unique_strings = df[str_col].unique().tolist()
        
        # Split strings into batches for parallel processing
        batch_size = max(1, len(unique_strings) // (num_cores * self.BATCHES_PER_CORE))
        batches = [unique_strings[i:i + batch_size] for i in range(0, len(unique_strings), batch_size)]
        
        # Prepare batch data with min suspicion score
        batch_data = [(batch, self.MIN_SUSPICION_SCORE) for batch in batches]
        
        # Process batches in parallel
        try:
            with Pool(processes=num_cores) as pool:
                batch_results = pool.map(self._process_entropy_batch, batch_data)
        except Exception:
            # Fall back to threading for Jupyter notebook compatibility
            with ThreadPoolExecutor(max_workers=num_cores) as executor:
                batch_results = list(executor.map(self._process_entropy_batch, batch_data))
        
        # Flatten results
        results = []
        for batch_result in batch_results:
            results.extend(batch_result)
        
        # Create result DataFrame
        result_df = pd.DataFrame(results)
        
        if result_df.empty:
            return result_df
        
        # Sort by suspicion score (descending)
        result_df = result_df.sort_values('suspicion_score', ascending=False)
        
        # Remove duplicates
        result_df = result_df.drop_duplicates(subset=['target_string'], keep='first')
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate entropy visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Create scatter plot: entropy vs string length
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['string_length'],
            y=result_df['entropy_score'],
            mode='markers',
            marker=dict(
                size=8,
                color=result_df['suspicion_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Suspicion<br>Score")
            ),
            text=[f"String: {result_df.iloc[i]['target_string'][:50]}{'...' if len(result_df.iloc[i]['target_string']) > 50 else ''}<br>Length: {result_df.iloc[i]['string_length']}<br>Entropy: {result_df.iloc[i]['entropy_score']:.2f}<br>Score: {result_df.iloc[i]['suspicion_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Entropy Analysis: High-Entropy Strings",
            xaxis_title="String Length",
            yaxis_title="Entropy Score (bits)",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for EntropyStrategy output columns."""
        return {
            'target_string': 'The string value being analyzed (e.g., domain name, DNS query)',
            'string_length': 'Number of characters in the string. Very long strings (50+ characters) may indicate data exfiltration through DNS tunneling',
            'entropy_score': 'Shannon entropy measuring randomness (0-8 bits). Higher values indicate more random/encoded data. Normal domains typically have entropy 3-4, while tunneled/DGA domains often exceed 4.5 bits',
            'suspicion_score': 'Overall suspiciousness score (0-100) combining entropy and length. Higher scores suggest DNS tunneling, Domain Generation Algorithms (DGA), or encoded data. Scores ≥50 warrant investigation',
            'ml_cluster': '🤖 MACHINE LEARNING: Which pattern group this string belongs to (0-4). ML groups similar suspicious strings together to identify malware families or attack campaigns. Requires 50+ suspicious strings for clustering',
            'ml_cluster_risk': '🤖 ML CLUSTER RISK: Risk level of this pattern cluster (CRITICAL/HIGH/MEDIUM). Shows if your cluster contains highly suspicious or moderately suspicious strings on average',
            'ml_explanation': '🤖 ML CLUSTERING: Plain English explanation of this cluster including size, risk level, and pattern type (DGA domains, DNS tunneling, etc.). Helps identify if multiple strings are from the same attack'
        }


class ExfilStrategy(HuntStrategy):
    """
    Exfiltration Monitor - Detects data exfiltration by traffic ratio.
    
    Calculates the ratio of bytes_out/bytes_in to identify hosts
    behaving as "producers" rather than "consumers".
    """
    
    # Constant for pure upload cases (bytes_in = 0, bytes_out > 0)
    PURE_UPLOAD_RATIO = 999999.0
    # Minimum bytes threshold to filter noise (1KB)
    MIN_BYTES_THRESHOLD = 1000
    # Minimum exfiltration score to be considered suspicious
    MIN_EXFIL_SCORE = 50
    # Chunks per core for parallel processing (fewer chunks for groupby operations)
    CHUNKS_PER_CORE = 1
    
    def _get_name(self) -> str:
        return "Exfiltration Monitor (Producer/Consumer Ratio)"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'bytes_out', 'bytes_in']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Calculate upload/download ratio for each source IP.
        
        Uses a hybrid approach:
        1. Rule-based scoring (ratio thresholds, percentiles)
        2. ML-based outlier detection (Local Outlier Factor) for unusual traffic patterns
        
        Args:
            df: DataFrame with connection logs
            col_map: Mapping of {'source_ip': actual_col, 'bytes_out': actual_col,
                                  'bytes_in': actual_col}
        
        Returns:
            DataFrame with source_ip, total_bytes_out, total_bytes_in, exfil_ratio
            Plus ML columns: ml_outlier_score, ml_confidence, ml_explanation
        """
        # Map columns
        src_col = col_map['source_ip']
        bytes_out_col = col_map['bytes_out']
        bytes_in_col = col_map['bytes_in']
        
        # Group by source IP and sum bytes
        df = df.copy()
        df[bytes_out_col] = pd.to_numeric(df[bytes_out_col], errors='coerce').fillna(0)
        df[bytes_in_col] = pd.to_numeric(df[bytes_in_col], errors='coerce').fillna(0)
        
        result_df = df.groupby(src_col).agg({
            bytes_out_col: 'sum',
            bytes_in_col: 'sum'
        }).reset_index()
        
        result_df = result_df.rename(columns={
            src_col: 'source_ip',
            bytes_out_col: 'total_bytes_out',
            bytes_in_col: 'total_bytes_in'
        })
        
        # Filter out rows with minimal traffic (noise reduction)
        result_df = result_df[
            (result_df['total_bytes_out'] + result_df['total_bytes_in']) >= self.MIN_BYTES_THRESHOLD
        ]
        
        # Calculate ratio with better handling of edge cases
        result_df['exfil_ratio'] = np.where(
            result_df['total_bytes_in'] > 0,
            result_df['total_bytes_out'] / result_df['total_bytes_in'],
            # If bytes_in is 0 but bytes_out > 0, mark as pure upload
            np.where(
                result_df['total_bytes_out'] > 0,
                self.PURE_UPLOAD_RATIO,
                0.0
            )
        )
        
        # Add total traffic for additional context
        result_df['total_bytes'] = result_df['total_bytes_out'] + result_df['total_bytes_in']
        
        # Calculate percentile rank for bytes_out (0-100)
        # This helps identify outliers
        result_df['upload_percentile'] = result_df['total_bytes_out'].rank(pct=True) * 100
        
        # Calculate exfiltration score (0-100) based on multiple factors
        result_df['exfil_score'] = 0.0
        
        # Factor 1: High upload ratio (50 points)
        result_df.loc[result_df['exfil_ratio'] >= 10, 'exfil_score'] += 50
        result_df.loc[(result_df['exfil_ratio'] >= 5) & (result_df['exfil_ratio'] < 10), 'exfil_score'] += 35
        result_df.loc[(result_df['exfil_ratio'] >= 2) & (result_df['exfil_ratio'] < 5), 'exfil_score'] += 20
        
        # Factor 2: High upload volume (30 points)
        result_df.loc[result_df['upload_percentile'] >= 95, 'exfil_score'] += 30
        result_df.loc[(result_df['upload_percentile'] >= 90) & (result_df['upload_percentile'] < 95), 'exfil_score'] += 20
        result_df.loc[(result_df['upload_percentile'] >= 80) & (result_df['upload_percentile'] < 90), 'exfil_score'] += 10
        
        # Factor 3: Significant total traffic (20 points)
        result_df.loc[result_df['total_bytes'] >= 10_000_000, 'exfil_score'] += 20  # 10MB+
        result_df.loc[(result_df['total_bytes'] >= 1_000_000) & (result_df['total_bytes'] < 10_000_000), 'exfil_score'] += 10  # 1MB+
        
        # Apply ML outlier detection if we have enough data
        if not result_df.empty and HAS_SKLEARN and len(result_df) >= ML_MIN_SAMPLES:
            result_df = self._apply_ml_outlier_detection(result_df)
        else:
            result_df['ml_outlier_score'] = 0.0
            result_df['ml_confidence'] = 'N/A (insufficient data or sklearn not available)'
            result_df['ml_explanation'] = 'Rule-based detection only - need 50+ hosts for ML outlier analysis'
        
        # Filter to high-confidence exfiltration
        result_df = result_df[result_df['exfil_score'] >= self.MIN_EXFIL_SCORE]
        
        # Sort by exfil_score (descending)
        result_df = result_df.sort_values('exfil_score', ascending=False)
        
        return result_df
    
    def _apply_ml_outlier_detection(self, result_df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply Local Outlier Factor (LOF) to detect unusual traffic patterns.
        
        LOF is a density-based algorithm that identifies hosts whose traffic
        behavior significantly differs from their neighbors, indicating
        potential data exfiltration.
        
        Args:
            result_df: DataFrame with rule-based exfiltration analysis results
        
        Returns:
            DataFrame with additional ML columns: ml_outlier_score, ml_confidence, ml_explanation
        """
        # Feature engineering for outlier detection
        # Use log scale for bytes to handle wide range of values
        ml_features = ['total_bytes_out', 'total_bytes_in', 'exfil_ratio', 'total_bytes']
        X = result_df[ml_features].copy()
        
        # Cap extreme ratios for better ML performance
        X['exfil_ratio'] = X['exfil_ratio'].clip(upper=100)
        
        # Apply log transformation to byte counts (add 1 to avoid log(0))
        X['total_bytes_out'] = np.log1p(X['total_bytes_out'])
        X['total_bytes_in'] = np.log1p(X['total_bytes_in'])
        X['total_bytes'] = np.log1p(X['total_bytes'])
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Train Local Outlier Factor model
        # n_neighbors=20 works well for most datasets
        # contamination='auto' lets LOF determine outlier threshold
        lof = LocalOutlierFactor(
            n_neighbors=min(20, len(result_df) - 1),
            contamination='auto',
            novelty=False  # We're detecting outliers in training set
        )
        
        # Fit and predict (-1 = outlier, 1 = inlier)
        outlier_predictions = lof.fit_predict(X_scaled)
        
        # Get negative outlier factor scores (more negative = more outlier-like)
        # Note: negative_outlier_factor_ is only available after fit_predict
        outlier_scores_raw = lof.negative_outlier_factor_
        
        # Convert to 0-100 scale where higher = more outlier-like
        # LOF scores are negative, closer to -1 is inlier, more negative is outlier
        # We'll normalize using percentile ranking
        from scipy.stats import rankdata
        # Invert so more negative scores get higher ranks
        ml_outlier_score = (rankdata(-outlier_scores_raw) / len(outlier_scores_raw)) * 100
        
        result_df['ml_outlier_score'] = ml_outlier_score
        result_df['ml_is_outlier'] = (outlier_predictions == -1)
        
        # Generate explanations
        ml_confidence_list = []
        ml_explanation_list = []
        
        for idx, row in result_df.iterrows():
            score = row['ml_outlier_score']
            is_outlier = row['ml_is_outlier']
            
            if is_outlier and score >= 75:
                confidence = "HIGH"
                explanation = "🔴 ML HIGH CONFIDENCE: This host's traffic pattern is extremely unusual compared to others. Upload/download ratio and volume are outliers."
            elif is_outlier and score >= 50:
                confidence = "MEDIUM"
                explanation = "🟡 ML MEDIUM CONFIDENCE: Moderate outlier detected. Traffic behavior differs from typical patterns."
            elif is_outlier:
                confidence = "LOW"
                explanation = "🟢 ML LOW CONFIDENCE: Slight outlier but not dramatically different from other hosts."
            else:
                confidence = "NORMAL"
                explanation = f"ℹ️ ML considers this traffic pattern normal (score: {score:.1f}/100). Rule-based logic flagged it based on ratio thresholds."
            
            # Feature contribution
            feature_vals = {
                'upload_ratio': min(row['exfil_ratio'] / 10.0, 1.0),  # Normalize
                'upload_volume': row['upload_percentile'] / 100.0,
                'total_traffic': min(row['total_bytes'] / 10_000_000.0, 1.0)
            }
            
            feature_explanation = get_feature_importance_explanation(feature_vals)
            explanation += f" {feature_explanation}"
            
            ml_confidence_list.append(confidence)
            ml_explanation_list.append(explanation)
        
        result_df['ml_confidence'] = ml_confidence_list
        result_df['ml_explanation'] = ml_explanation_list
        
        # Drop internal column
        result_df = result_df.drop(columns=['ml_is_outlier'])
        
        return result_df
    
    @staticmethod
    def _process_exfil_chunk(chunk_data):
        """
        Process a chunk of IPs for exfiltration analysis.
        
        This static method is used for parallel processing.
        
        Args:
            chunk_data: Tuple of (df_chunk, src_col, bytes_out_col, bytes_in_col, 
                                  min_bytes_threshold, pure_upload_ratio, min_exfil_score)
        
        Returns:
            DataFrame with analysis results for this chunk
        """
        (df_chunk, src_col, bytes_out_col, bytes_in_col, 
         min_bytes_threshold, pure_upload_ratio, min_exfil_score) = chunk_data
        
        # Group by source IP and sum bytes
        result_df = df_chunk.groupby(src_col).agg({
            bytes_out_col: 'sum',
            bytes_in_col: 'sum'
        }).reset_index()
        
        result_df = result_df.rename(columns={
            src_col: 'source_ip',
            bytes_out_col: 'total_bytes_out',
            bytes_in_col: 'total_bytes_in'
        })
        
        # Filter out rows with minimal traffic
        result_df = result_df[
            (result_df['total_bytes_out'] + result_df['total_bytes_in']) >= min_bytes_threshold
        ]
        
        if result_df.empty:
            return result_df
        
        # Calculate ratio
        result_df['exfil_ratio'] = np.where(
            result_df['total_bytes_in'] > 0,
            result_df['total_bytes_out'] / result_df['total_bytes_in'],
            np.where(
                result_df['total_bytes_out'] > 0,
                pure_upload_ratio,
                0.0
            )
        )
        
        # Add total traffic
        result_df['total_bytes'] = result_df['total_bytes_out'] + result_df['total_bytes_in']
        
        return result_df
    
    def parallel_analyze(self, df: pd.DataFrame, col_map: dict, num_cores: int = 4) -> pd.DataFrame:
        """
        Parallel implementation of exfiltration analysis.
        
        Args:
            df: DataFrame with connection logs
            col_map: Mapping of column names
            num_cores: Number of CPU cores to use
        
        Returns:
            DataFrame with analysis results
        """
        # Map columns
        src_col = col_map['source_ip']
        bytes_out_col = col_map['bytes_out']
        bytes_in_col = col_map['bytes_in']
        
        # Prepare data
        df = df.copy()
        df[bytes_out_col] = pd.to_numeric(df[bytes_out_col], errors='coerce').fillna(0)
        df[bytes_in_col] = pd.to_numeric(df[bytes_in_col], errors='coerce').fillna(0)
        
        # Split data into chunks by source IP for parallel processing
        # Using fewer chunks (CHUNKS_PER_CORE) because groupby operations are more expensive
        unique_ips = df[src_col].unique()
        num_chunks = max(1, num_cores * self.CHUNKS_PER_CORE)
        chunk_size = max(1, len(unique_ips) // num_chunks)
        ip_chunks = [unique_ips[i:i + chunk_size] for i in range(0, len(unique_ips), chunk_size)]
        
        # Create DataFrame chunks
        df_chunks = [df[df[src_col].isin(ip_chunk)] for ip_chunk in ip_chunks]
        
        # Prepare chunk data
        chunk_data = [
            (chunk, src_col, bytes_out_col, bytes_in_col, 
             self.MIN_BYTES_THRESHOLD, self.PURE_UPLOAD_RATIO, self.MIN_EXFIL_SCORE)
            for chunk in df_chunks
        ]
        
        # Process chunks in parallel
        try:
            with Pool(processes=num_cores) as pool:
                chunk_results = pool.map(self._process_exfil_chunk, chunk_data)
        except Exception:
            # Fall back to threading for Jupyter notebook compatibility
            with ThreadPoolExecutor(max_workers=num_cores) as executor:
                chunk_results = list(executor.map(self._process_exfil_chunk, chunk_data))
        
        # Combine results from all chunks
        # Filter out empty DataFrames before concatenation
        non_empty_results = [df for df in chunk_results if not df.empty]
        
        if not non_empty_results:
            return pd.DataFrame()
        
        result_df = pd.concat(non_empty_results, ignore_index=True)
        
        # Calculate percentile rank across all results
        result_df['upload_percentile'] = result_df['total_bytes_out'].rank(pct=True) * 100
        
        # Calculate exfiltration score
        result_df['exfil_score'] = 0.0
        
        # Factor 1: High upload ratio (50 points)
        result_df.loc[result_df['exfil_ratio'] >= 10, 'exfil_score'] += 50
        result_df.loc[(result_df['exfil_ratio'] >= 5) & (result_df['exfil_ratio'] < 10), 'exfil_score'] += 35
        result_df.loc[(result_df['exfil_ratio'] >= 2) & (result_df['exfil_ratio'] < 5), 'exfil_score'] += 20
        
        # Factor 2: High upload volume (30 points)
        result_df.loc[result_df['upload_percentile'] >= 95, 'exfil_score'] += 30
        result_df.loc[(result_df['upload_percentile'] >= 90) & (result_df['upload_percentile'] < 95), 'exfil_score'] += 20
        result_df.loc[(result_df['upload_percentile'] >= 80) & (result_df['upload_percentile'] < 90), 'exfil_score'] += 10
        
        # Factor 3: Significant total traffic (20 points)
        result_df.loc[result_df['total_bytes'] >= 10_000_000, 'exfil_score'] += 20
        result_df.loc[(result_df['total_bytes'] >= 1_000_000) & (result_df['total_bytes'] < 10_000_000), 'exfil_score'] += 10
        
        # Filter to high-confidence exfiltration
        result_df = result_df[result_df['exfil_score'] >= self.MIN_EXFIL_SCORE]
        
        # Sort by exfil_score
        result_df = result_df.sort_values('exfil_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate exfiltration visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Create scatter plot: bytes_out vs bytes_in with ratio coloring
        fig = go.Figure()
        
        # Convert to MB for better readability
        result_df['bytes_out_mb'] = result_df['total_bytes_out'] / 1_000_000
        result_df['bytes_in_mb'] = result_df['total_bytes_in'] / 1_000_000
        
        fig.add_trace(go.Scatter(
            x=result_df['bytes_in_mb'],
            y=result_df['bytes_out_mb'],
            mode='markers',
            marker=dict(
                size=10,
                color=result_df['exfil_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Exfil<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Upload: {result_df.iloc[i]['bytes_out_mb']:.2f} MB<br>Download: {result_df.iloc[i]['bytes_in_mb']:.2f} MB<br>Ratio: {result_df.iloc[i]['exfil_ratio']:.2f}<br>Score: {result_df.iloc[i]['exfil_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        # Add diagonal line for reference (equal upload/download)
        max_val = max(result_df['bytes_in_mb'].max(), result_df['bytes_out_mb'].max())
        fig.add_trace(go.Scatter(
            x=[0, max_val],
            y=[0, max_val],
            mode='lines',
            line=dict(color='gray', dash='dash'),
            showlegend=False,
            hoverinfo='skip'
        ))
        
        fig.update_layout(
            title="Exfiltration Analysis: Upload vs Download (MB)",
            xaxis_title="Total Downloaded (MB)",
            yaxis_title="Total Uploaded (MB)",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for ExfilStrategy output columns."""
        return {
            'source_ip': 'The IP address generating the network traffic',
            'total_bytes_out': 'Total bytes uploaded/sent by this source (in bytes)',
            'total_bytes_in': 'Total bytes downloaded/received by this source (in bytes)',
            'exfil_ratio': 'Upload-to-download ratio. Normal users typically download more than upload (ratio < 1). Ratios ≥2 indicate the host is uploading significantly more data than receiving, which may suggest data exfiltration',
            'total_bytes': 'Sum of uploaded and downloaded bytes, showing total network activity volume',
            'upload_percentile': "Percentile rank (0-100) of this source's upload volume compared to all sources. Values ≥90 indicate this source is in the top 10% of uploaders",
            'exfil_score': 'Overall exfiltration suspiciousness score (0-100) based on ratio, upload volume, and total traffic. Higher scores indicate stronger evidence of data exfiltration. Scores ≥50 suggest potential data theft worth investigating',
            'ml_outlier_score': '🤖 MACHINE LEARNING: How unusual this traffic pattern is compared to all other hosts (0-100). Higher scores mean ML identified dramatically different upload/download behavior. Requires 50+ hosts for ML analysis',
            'ml_confidence': '🤖 ML CONFIDENCE LEVEL: How confident the machine learning model is that this is an outlier (HIGH/MEDIUM/LOW/NORMAL). Shows whether ML agrees with rule-based exfiltration detection',
            'ml_explanation': '🤖 ML REASONING: Plain English explanation using Local Outlier Factor (density-based outlier detection). Describes why this host traffic pattern differs from neighbors, including which features (upload ratio, volume, total traffic) are unusual'
        }


class PortScanStrategy(HuntStrategy):
    """
    Port Scan Detector - Identifies port scanning activity.
    
    Detects hosts scanning multiple ports on multiple targets by analyzing
    connection patterns. Classic indicator of reconnaissance activity.
    """
    
    MIN_UNIQUE_PORTS = 10
    MIN_SCAN_SCORE = 50
    
    def _get_name(self) -> str:
        return "Port Scan Detector (Reconnaissance)"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'dest_ip', 'dest_port']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze connection patterns to detect port scanning.
        
        Args:
            df: DataFrame with connection logs
            col_map: Mapping of {'source_ip': actual_col, 'dest_ip': actual_col,
                                  'dest_port': actual_col}
        
        Returns:
            DataFrame with source_ip, unique_ports, unique_targets, scan_score
        """
        src_col = col_map['source_ip']
        dst_col = col_map['dest_ip']
        port_col = col_map['dest_port']
        
        df = df.copy()
        df[port_col] = pd.to_numeric(df[port_col], errors='coerce')
        df = df.dropna(subset=[port_col])
        
        # Group by source IP and analyze scanning patterns
        results = []
        for src_ip, group in df.groupby(src_col):
            unique_ports = group[port_col].nunique()
            unique_targets = group[dst_col].nunique()
            total_connections = len(group)
            
            # Filter noise - must scan multiple ports
            if unique_ports < self.MIN_UNIQUE_PORTS:
                continue
            
            # Calculate port diversity (how many different ports per target)
            port_diversity = unique_ports / max(unique_targets, 1)
            
            # Calculate scan score (0-100)
            scan_score = 0.0
            
            # Factor 1: Number of unique ports (40 points)
            if unique_ports >= 100:
                scan_score += 40
            elif unique_ports >= 50:
                scan_score += 30
            elif unique_ports >= 20:
                scan_score += 20
            elif unique_ports >= 10:
                scan_score += 10
            
            # Factor 2: Port diversity (30 points)
            # High diversity = scanning many ports per target
            if port_diversity >= 10:
                scan_score += 30
            elif port_diversity >= 5:
                scan_score += 20
            elif port_diversity >= 2:
                scan_score += 10
            
            # Factor 3: Multiple targets (30 points)
            if unique_targets >= 10:
                scan_score += 30
            elif unique_targets >= 5:
                scan_score += 20
            elif unique_targets >= 2:
                scan_score += 10
            
            if scan_score >= self.MIN_SCAN_SCORE:
                results.append({
                    'source_ip': src_ip,
                    'unique_ports': unique_ports,
                    'unique_targets': unique_targets,
                    'total_connections': total_connections,
                    'port_diversity': port_diversity,
                    'scan_score': min(scan_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('scan_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate port scan visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['unique_ports'],
            y=result_df['unique_targets'],
            mode='markers',
            marker=dict(
                size=10,
                color=result_df['scan_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Scan<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Ports: {result_df.iloc[i]['unique_ports']}<br>Targets: {result_df.iloc[i]['unique_targets']}<br>Score: {result_df.iloc[i]['scan_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Port Scan Detection: Unique Ports vs Unique Targets",
            xaxis_title="Unique Ports Scanned",
            yaxis_title="Unique Target IPs",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for PortScanStrategy output columns."""
        return {
            'source_ip': 'The IP address performing the port scanning activity',
            'unique_ports': 'Number of distinct destination ports contacted. High values (20+) suggest systematic scanning',
            'unique_targets': 'Number of distinct target IP addresses scanned. Multiple targets indicate network-wide reconnaissance',
            'total_connections': 'Total number of connection attempts made by this source',
            'port_diversity': 'Average ports scanned per target. Values ≥5 indicate aggressive scanning across the port range',
            'scan_score': 'Overall port scanning suspiciousness score (0-100). Higher scores indicate reconnaissance activity. Scores ≥50 suggest active port scanning that should be investigated for potential attack preparation'
        }


class BruteForceStrategy(HuntStrategy):
    """
    Brute Force Detector - Identifies authentication attack attempts.
    
    Analyzes authentication logs to detect brute force attacks by
    looking for high failure rates and rapid-fire attempts.
    """
    
    MIN_ATTEMPTS = 10
    MIN_BRUTE_SCORE = 50
    
    def _get_name(self) -> str:
        return "Brute Force Detector (Authentication Attacks)"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'dest_ip', 'status']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze authentication patterns to detect brute force attacks.
        
        Args:
            df: DataFrame with authentication logs
            col_map: Mapping of {'source_ip': actual_col, 'dest_ip': actual_col,
                                  'status': actual_col (success/failure indicator)}
        
        Returns:
            DataFrame with source_ip, dest_ip, total_attempts, failed_attempts, 
                     failure_rate, brute_force_score
        """
        src_col = col_map['source_ip']
        dst_col = col_map['dest_ip']
        status_col = col_map['status']
        
        df = df.copy()
        
        # Determine what constitutes a failure
        # Common patterns: "failed", "failure", "fail", "rejected", "denied", "error"
        # or numeric codes like 401, 403, etc. (using word boundaries for exact matches)
        df['is_failure'] = df[status_col].astype(str).str.lower().str.contains(
            r'\bfail|\breject|\bdenied|\berror|\b401\b|\b403\b|\binvalid|\bwrong', 
            na=False, 
            regex=True
        )
        
        # Group by source and destination
        results = []
        for (src_ip, dst_ip), group in df.groupby([src_col, dst_col]):
            total_attempts = len(group)
            failed_attempts = group['is_failure'].sum()
            
            # Filter noise - need minimum attempts
            if total_attempts < self.MIN_ATTEMPTS:
                continue
            
            # Calculate failure rate
            failure_rate = failed_attempts / total_attempts if total_attempts > 0 else 0
            
            # Calculate brute force score (0-100)
            brute_score = 0.0
            
            # Factor 1: High failure rate (50 points)
            if failure_rate >= 0.9:  # 90%+ failure
                brute_score += 50
            elif failure_rate >= 0.7:  # 70%+ failure
                brute_score += 35
            elif failure_rate >= 0.5:  # 50%+ failure
                brute_score += 20
            
            # Factor 2: Volume of attempts (30 points)
            if total_attempts >= 100:
                brute_score += 30
            elif total_attempts >= 50:
                brute_score += 20
            elif total_attempts >= 20:
                brute_score += 10
            
            # Factor 3: Failed attempts count (20 points)
            if failed_attempts >= 50:
                brute_score += 20
            elif failed_attempts >= 25:
                brute_score += 15
            elif failed_attempts >= 10:
                brute_score += 10
            
            if brute_score >= self.MIN_BRUTE_SCORE:
                results.append({
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'total_attempts': total_attempts,
                    'failed_attempts': int(failed_attempts),
                    'successful_attempts': int(total_attempts - failed_attempts),
                    'failure_rate': failure_rate,
                    'brute_force_score': min(brute_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('brute_force_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate brute force visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['total_attempts'],
            y=result_df['failure_rate'] * 100,  # Convert to percentage
            mode='markers',
            marker=dict(
                size=10,
                color=result_df['brute_force_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Brute<br>Force<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Target: {result_df.iloc[i]['dest_ip']}<br>Attempts: {result_df.iloc[i]['total_attempts']}<br>Failures: {result_df.iloc[i]['failed_attempts']}<br>Rate: {result_df.iloc[i]['failure_rate']*100:.1f}%<br>Score: {result_df.iloc[i]['brute_force_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Brute Force Detection: Attempts vs Failure Rate",
            xaxis_title="Total Authentication Attempts",
            yaxis_title="Failure Rate (%)",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for BruteForceStrategy output columns."""
        return {
            'source_ip': 'The IP address attempting authentication',
            'dest_ip': 'The target system being attacked',
            'total_attempts': 'Total number of authentication attempts observed',
            'failed_attempts': 'Number of authentication attempts that failed',
            'successful_attempts': 'Number of authentication attempts that succeeded',
            'failure_rate': 'Percentage of failed attempts (0-1). Values ≥0.7 indicate likely brute force attempts where attacker is guessing credentials',
            'brute_force_score': 'Overall brute force attack suspiciousness score (0-100). Higher scores indicate credential stuffing or password spraying attacks. Scores ≥50 suggest active authentication attacks requiring immediate investigation'
        }


class TunnelingStrategy(HuntStrategy):
    """
    Protocol Tunneling Detector - Identifies unusual protocol usage.
    
    Detects potential protocol tunneling by analyzing traffic patterns,
    unusual ports, and high data volumes on non-standard services.
    """
    
    MIN_TUNNEL_SCORE = 50
    MIN_BYTES_THRESHOLD = 10000  # 10KB
    
    # Common legitimate ports for various protocols
    STANDARD_PORTS = {
        'http': [80, 8080, 8000, 8888],
        'https': [443, 8443],
        'dns': [53],
        'ssh': [22],
        'ftp': [20, 21],
        'smtp': [25, 587],
        'pop3': [110, 995],
        'imap': [143, 993],
        'rdp': [3389],
        'smb': [139, 445]
    }
    
    def _get_name(self) -> str:
        return "Protocol Tunneling Detector (Covert Channels)"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'dest_ip', 'dest_port', 'bytes_total']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze traffic patterns to detect protocol tunneling.
        
        Args:
            df: DataFrame with connection logs
            col_map: Mapping of column names
        
        Returns:
            DataFrame with suspicious tunneling activity
        """
        src_col = col_map['source_ip']
        dst_col = col_map['dest_ip']
        port_col = col_map['dest_port']
        bytes_col = col_map['bytes_total']
        
        df = df.copy()
        df[port_col] = pd.to_numeric(df[port_col], errors='coerce')
        df[bytes_col] = pd.to_numeric(df[bytes_col], errors='coerce').fillna(0)
        df = df.dropna(subset=[port_col])
        
        # Filter out minimal traffic
        df = df[df[bytes_col] >= self.MIN_BYTES_THRESHOLD]
        
        # Flatten standard ports list
        all_standard_ports = set()
        for ports in self.STANDARD_PORTS.values():
            all_standard_ports.update(ports)
        
        # Identify non-standard ports
        df['is_nonstandard'] = ~df[port_col].isin(all_standard_ports)
        
        # Group by source, dest, and port
        results = []
        for (src_ip, dst_ip, port), group in df.groupby([src_col, dst_col, port_col]):
            total_bytes = group[bytes_col].sum()
            connection_count = len(group)
            avg_bytes_per_conn = total_bytes / connection_count if connection_count > 0 else 0
            is_nonstandard = group['is_nonstandard'].iloc[0]
            
            # Calculate tunnel score (0-100)
            tunnel_score = 0.0
            
            # Factor 1: Non-standard port usage (30 points)
            if is_nonstandard:
                tunnel_score += 30
            
            # Factor 2: High data volume (40 points)
            # Large data transfers on unusual ports are suspicious
            if total_bytes >= 100_000_000:  # 100MB+
                tunnel_score += 40
            elif total_bytes >= 10_000_000:  # 10MB+
                tunnel_score += 30
            elif total_bytes >= 1_000_000:  # 1MB+
                tunnel_score += 20
            
            # Factor 3: Connection pattern (30 points)
            # Many connections with consistent sizes suggest tunneling
            if connection_count >= 50:
                tunnel_score += 20
                # Check for consistent connection sizes (low variance)
                if connection_count > 1:
                    byte_variance = group[bytes_col].std() / group[bytes_col].mean() if group[bytes_col].mean() > 0 else 0
                    if byte_variance < 0.3:  # Low variance = consistent sizes
                        tunnel_score += 10
            elif connection_count >= 20:
                tunnel_score += 10
            
            # Flag if score is high enough
            # Non-standard ports get preferential scoring, but allow high-scoring
            # standard ports too (e.g., very high volume on HTTPS could be tunneling)
            if tunnel_score >= self.MIN_TUNNEL_SCORE:
                results.append({
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'dest_port': int(port),
                    'total_bytes': total_bytes,
                    'connection_count': connection_count,
                    'avg_bytes_per_conn': avg_bytes_per_conn,
                    'is_standard_port': not is_nonstandard,
                    'tunnel_score': min(tunnel_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('tunnel_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate tunneling visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Convert bytes to MB for readability
        result_df['total_mb'] = result_df['total_bytes'] / 1_000_000
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['dest_port'],
            y=result_df['total_mb'],
            mode='markers',
            marker=dict(
                size=10,
                color=result_df['tunnel_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Tunnel<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Dest: {result_df.iloc[i]['dest_ip']}<br>Port: {result_df.iloc[i]['dest_port']}<br>Data: {result_df.iloc[i]['total_mb']:.2f} MB<br>Connections: {result_df.iloc[i]['connection_count']}<br>Score: {result_df.iloc[i]['tunnel_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Protocol Tunneling Detection: Port vs Data Volume",
            xaxis_title="Destination Port",
            yaxis_title="Total Data Transferred (MB)",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for TunnelingStrategy output columns."""
        return {
            'source_ip': 'The IP address initiating the potentially tunneled traffic',
            'dest_ip': 'The destination IP address for the tunneled traffic',
            'dest_port': 'The destination port being used. Non-standard ports with high traffic may indicate tunneling',
            'total_bytes': 'Total data volume transferred on this connection (in bytes)',
            'connection_count': 'Number of connections established on this port',
            'avg_bytes_per_conn': 'Average bytes per connection. Consistent sizes across many connections suggest automated tunneling',
            'is_standard_port': 'Whether this is a commonly-used port. False (non-standard) ports are more suspicious, but high-volume standard ports can also indicate tunneling',
            'tunnel_score': 'Overall protocol tunneling suspiciousness score (0-100). Higher scores indicate covert channel activity like DNS tunneling, SSH tunneling, or other protocol encapsulation. Scores ≥50 suggest unusual traffic patterns worth investigating for data hiding or command-and-control'
        }


class LateralMovementStrategy(HuntStrategy):
    """
    Lateral Movement Detector - Identifies suspicious lateral movement patterns.
    
    Detects potential lateral movement by analyzing authentication and connection
    patterns across multiple hosts. Looks for single sources accessing many targets
    in short time windows.
    """
    
    MIN_UNIQUE_TARGETS = 5
    MIN_LATERAL_SCORE = 50
    TIME_WINDOW_HOURS = 1  # Time window to look for rapid movement
    MIN_TIME_SPAN_HOURS = 0.1  # Minimum time span (6 minutes) to avoid division by zero
    
    def _get_name(self) -> str:
        return "Lateral Movement Detector (Privilege Escalation)"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'dest_ip']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze connection patterns to detect lateral movement.
        
        Args:
            df: DataFrame with connection/authentication logs
            col_map: Mapping of column names
        
        Returns:
            DataFrame with suspicious lateral movement activity
        """
        ts_col = col_map['timestamp']
        src_col = col_map['source_ip']
        dst_col = col_map['dest_ip']
        
        df = df.copy()
        df[ts_col] = pd.to_datetime(df[ts_col])
        df = df.sort_values(ts_col)
        
        results = []
        
        # Group by source IP
        for src_ip, group in df.groupby(src_col):
            unique_targets = group[dst_col].nunique()
            total_connections = len(group)
            
            # Filter noise - need minimum targets
            if unique_targets < self.MIN_UNIQUE_TARGETS:
                continue
            
            # Calculate time span
            time_span = (group[ts_col].max() - group[ts_col].min()).total_seconds() / 3600  # hours
            
            # Calculate targets per hour (use MIN_TIME_SPAN_HOURS to avoid division by zero)
            targets_per_hour = unique_targets / max(time_span, self.MIN_TIME_SPAN_HOURS)
            
            # Calculate lateral movement score (0-100)
            lateral_score = 0.0
            
            # Factor 1: Number of unique targets (40 points)
            if unique_targets >= 20:
                lateral_score += 40
            elif unique_targets >= 10:
                lateral_score += 30
            elif unique_targets >= 5:
                lateral_score += 20
            
            # Factor 2: Speed of movement (30 points)
            # Rapid movement (many targets per hour) is suspicious
            if targets_per_hour >= 10:
                lateral_score += 30
            elif targets_per_hour >= 5:
                lateral_score += 20
            elif targets_per_hour >= 2:
                lateral_score += 10
            
            # Factor 3: Connection volume (30 points)
            if total_connections >= 100:
                lateral_score += 30
            elif total_connections >= 50:
                lateral_score += 20
            elif total_connections >= 20:
                lateral_score += 10
            
            if lateral_score >= self.MIN_LATERAL_SCORE:
                # Get first and last timestamps
                first_seen = group[ts_col].min()
                last_seen = group[ts_col].max()
                
                results.append({
                    'source_ip': src_ip,
                    'unique_targets': unique_targets,
                    'total_connections': total_connections,
                    'time_span_hours': time_span,
                    'targets_per_hour': targets_per_hour,
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'lateral_score': min(lateral_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('lateral_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate lateral movement visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['unique_targets'],
            y=result_df['targets_per_hour'],
            mode='markers',
            marker=dict(
                size=10,
                color=result_df['lateral_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Lateral<br>Movement<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Targets: {result_df.iloc[i]['unique_targets']}<br>Speed: {result_df.iloc[i]['targets_per_hour']:.2f} targets/hr<br>Score: {result_df.iloc[i]['lateral_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Lateral Movement: Unique Targets vs Movement Speed",
            xaxis_title="Unique Target IPs",
            yaxis_title="Targets per Hour",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for LateralMovementStrategy output columns."""
        return {
            'source_ip': 'The IP address moving laterally across the network',
            'unique_targets': 'Number of distinct destination IPs contacted. High values indicate broad network access',
            'total_connections': 'Total connection attempts made',
            'time_span_hours': 'Time period (in hours) over which the lateral movement occurred',
            'targets_per_hour': 'Speed of lateral movement. Values ≥5 indicate rapid reconnaissance or automated spreading',
            'first_seen': 'Timestamp of first observed connection',
            'last_seen': 'Timestamp of last observed connection',
            'lateral_score': 'Overall lateral movement suspiciousness score (0-100). Higher scores indicate potential privilege escalation, network reconnaissance, or malware spreading. Scores ≥50 suggest an attacker moving through the network'
        }


class DataHoardingStrategy(HuntStrategy):
    """
    Data Hoarding Detector - Identifies unusual data collection patterns.
    
    Detects potential data theft preparation by identifying hosts that are
    accessing or downloading unusually large volumes of data, or accessing
    many different data sources.
    """
    
    MIN_HOARDING_SCORE = 50
    # Minimum download size threshold - filters out small routine downloads (1MB)
    MIN_DOWNLOAD_THRESHOLD_BYTES = 1_000_000
    
    def _get_name(self) -> str:
        return "Data Hoarding Detector (Theft Preparation)"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'dest_ip', 'bytes_in']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze download patterns to detect data hoarding.
        
        Args:
            df: DataFrame with connection logs
            col_map: Mapping of column names
        
        Returns:
            DataFrame with suspicious data hoarding activity
        """
        src_col = col_map['source_ip']
        dst_col = col_map['dest_ip']
        bytes_col = col_map['bytes_in']
        
        df = df.copy()
        df[bytes_col] = pd.to_numeric(df[bytes_col], errors='coerce').fillna(0)
        
        # Filter out minimal traffic (routine small downloads)
        df = df[df[bytes_col] >= self.MIN_DOWNLOAD_THRESHOLD_BYTES]
        
        results = []
        
        # Group by source IP
        for src_ip, group in df.groupby(src_col):
            total_bytes_downloaded = group[bytes_col].sum()
            unique_sources = group[dst_col].nunique()
            connection_count = len(group)
            avg_bytes_per_conn = total_bytes_downloaded / connection_count if connection_count > 0 else 0
            
            # Calculate hoarding score (0-100)
            hoarding_score = 0.0
            
            # Factor 1: Total data volume (40 points)
            if total_bytes_downloaded >= 1_000_000_000:  # 1GB+
                hoarding_score += 40
            elif total_bytes_downloaded >= 100_000_000:  # 100MB+
                hoarding_score += 30
            elif total_bytes_downloaded >= 10_000_000:  # 10MB+
                hoarding_score += 20
            
            # Factor 2: Number of different data sources (30 points)
            # Accessing many sources suggests systematic collection
            if unique_sources >= 20:
                hoarding_score += 30
            elif unique_sources >= 10:
                hoarding_score += 20
            elif unique_sources >= 5:
                hoarding_score += 10
            
            # Factor 3: Connection patterns (30 points)
            if connection_count >= 100:
                hoarding_score += 20
                # Check for consistent download sizes (bulk operations)
                if connection_count > 1:
                    mean_bytes = group[bytes_col].mean()
                    std_bytes = group[bytes_col].std()
                    # Handle edge cases: if both are 0 or mean is 0, skip CV calculation
                    if mean_bytes > 0:
                        byte_cv = std_bytes / mean_bytes
                        if byte_cv < 0.5:  # Consistent sizes
                            hoarding_score += 10
            elif connection_count >= 50:
                hoarding_score += 10
            
            if hoarding_score >= self.MIN_HOARDING_SCORE:
                results.append({
                    'source_ip': src_ip,
                    'total_bytes_downloaded': total_bytes_downloaded,
                    'unique_data_sources': unique_sources,
                    'connection_count': connection_count,
                    'avg_bytes_per_conn': avg_bytes_per_conn,
                    'hoarding_score': min(hoarding_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('hoarding_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate data hoarding visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Convert bytes to GB for readability
        result_df['total_gb'] = result_df['total_bytes_downloaded'] / 1_000_000_000
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['unique_data_sources'],
            y=result_df['total_gb'],
            mode='markers',
            marker=dict(
                size=10,
                color=result_df['hoarding_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Hoarding<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Downloaded: {result_df.iloc[i]['total_gb']:.2f} GB<br>Sources: {result_df.iloc[i]['unique_data_sources']}<br>Score: {result_df.iloc[i]['hoarding_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Data Hoarding: Data Sources vs Download Volume",
            xaxis_title="Unique Data Sources",
            yaxis_title="Total Downloaded (GB)",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for DataHoardingStrategy output columns."""
        return {
            'source_ip': 'The IP address downloading/collecting data',
            'total_bytes_downloaded': 'Total volume of data downloaded (in bytes)',
            'unique_data_sources': 'Number of different destination IPs accessed. High values suggest systematic data collection from multiple sources',
            'connection_count': 'Total number of connections made',
            'avg_bytes_per_conn': 'Average download size per connection. Large consistent sizes may indicate bulk file transfers',
            'hoarding_score': 'Overall data hoarding suspiciousness score (0-100). Higher scores indicate potential data theft preparation where an attacker is collecting data before exfiltration. Scores ≥50 suggest unusual bulk data collection patterns'
        }


class TimeAnomalyStrategy(HuntStrategy):
    """
    Time-Based Anomaly Detector - Identifies off-hours suspicious activity.
    
    Detects activity occurring outside normal business hours which may
    indicate unauthorized access, insider threats, or compromised accounts.
    
    Note: Business hours are defined as 8am-6pm Monday-Friday in the system's
    local timezone. Organizations with different schedules or global operations
    may need to adjust these constants or interpret results accordingly.
    """
    
    MIN_ANOMALY_SCORE = 50
    # Define business hours (24-hour format, local timezone)
    BUSINESS_START_HOUR = 8
    BUSINESS_END_HOUR = 18
    # Define business days (0=Monday, 6=Sunday)
    BUSINESS_DAYS = [0, 1, 2, 3, 4]  # Monday-Friday
    
    def _get_name(self) -> str:
        return "Time-Based Anomaly Detector (Off-Hours Activity)"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze activity timing to detect off-hours anomalies.
        
        Args:
            df: DataFrame with timestamped events
            col_map: Mapping of column names
        
        Returns:
            DataFrame with suspicious off-hours activity
        """
        ts_col = col_map['timestamp']
        src_col = col_map['source_ip']
        
        df = df.copy()
        df[ts_col] = pd.to_datetime(df[ts_col])
        
        # Extract time-based features
        df['hour'] = df[ts_col].dt.hour
        df['day_of_week'] = df[ts_col].dt.dayofweek
        df['is_weekend'] = ~df['day_of_week'].isin(self.BUSINESS_DAYS)
        df['is_off_hours'] = (df['hour'] < self.BUSINESS_START_HOUR) | (df['hour'] >= self.BUSINESS_END_HOUR)
        df['is_anomalous_time'] = df['is_weekend'] | df['is_off_hours']
        
        results = []
        
        # Group by source IP
        for src_ip, group in df.groupby(src_col):
            total_activity = len(group)
            off_hours_activity = group['is_anomalous_time'].sum()
            weekend_activity = group['is_weekend'].sum()
            late_night_activity = (group['hour'] < 6).sum()  # 12am-6am
            
            # Calculate off-hours percentage
            off_hours_pct = (off_hours_activity / total_activity) * 100 if total_activity > 0 else 0
            
            # Calculate anomaly score (0-100)
            anomaly_score = 0.0
            
            # Factor 1: High percentage of off-hours activity (50 points)
            if off_hours_pct >= 80:
                anomaly_score += 50
            elif off_hours_pct >= 60:
                anomaly_score += 35
            elif off_hours_pct >= 40:
                anomaly_score += 20
            
            # Factor 2: Late night activity (30 points)
            # Activity between midnight and 6am is especially suspicious
            late_night_pct = (late_night_activity / total_activity) * 100 if total_activity > 0 else 0
            if late_night_pct >= 50:
                anomaly_score += 30
            elif late_night_pct >= 30:
                anomaly_score += 20
            elif late_night_pct >= 10:
                anomaly_score += 10
            
            # Factor 3: Volume of activity (20 points)
            # More activity = more significant if it's off-hours
            if total_activity >= 100:
                anomaly_score += 20
            elif total_activity >= 50:
                anomaly_score += 15
            elif total_activity >= 20:
                anomaly_score += 10
            
            if anomaly_score >= self.MIN_ANOMALY_SCORE and off_hours_activity >= 5:
                # Get time distribution
                hour_dist = group['hour'].value_counts().to_dict()
                most_active_hours = sorted(hour_dist.items(), key=lambda x: x[1], reverse=True)[:3]
                
                results.append({
                    'source_ip': src_ip,
                    'total_activity': total_activity,
                    'off_hours_activity': int(off_hours_activity),
                    'off_hours_percentage': off_hours_pct,
                    'weekend_activity': int(weekend_activity),
                    'late_night_activity': int(late_night_activity),
                    'most_active_hours': ', '.join([f"{h}:00 ({c}x)" for h, c in most_active_hours]),
                    'anomaly_score': min(anomaly_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('anomaly_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate time anomaly visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['total_activity'],
            y=result_df['off_hours_percentage'],
            mode='markers',
            marker=dict(
                size=10,
                color=result_df['anomaly_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Anomaly<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Total Activity: {result_df.iloc[i]['total_activity']}<br>Off-Hours: {result_df.iloc[i]['off_hours_percentage']:.1f}%<br>Late Night: {result_df.iloc[i]['late_night_activity']}<br>Score: {result_df.iloc[i]['anomaly_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Time-Based Anomalies: Activity Volume vs Off-Hours Percentage",
            xaxis_title="Total Activity Count",
            yaxis_title="Off-Hours Activity (%)",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for TimeAnomalyStrategy output columns."""
        return {
            'source_ip': 'The IP address with anomalous timing patterns',
            'total_activity': 'Total number of activities/events observed',
            'off_hours_activity': 'Number of activities outside business hours (before 8am or after 6pm on weekdays, or anytime on weekends)',
            'off_hours_percentage': 'Percentage of total activity occurring off-hours. Values ≥60% are highly suspicious',
            'weekend_activity': 'Number of activities on weekends',
            'late_night_activity': 'Number of activities between midnight and 6am. Late night activity is especially suspicious',
            'most_active_hours': 'Top 3 most active hours with activity counts',
            'anomaly_score': 'Overall time-based anomaly score (0-100). Higher scores indicate suspicious off-hours access patterns typical of unauthorized access, insider threats, or compromised credentials. Scores ≥50 warrant investigation into why this account is active at unusual times'
        }


class GeoAnomalyStrategy(HuntStrategy):
    """
    Geo-Anomaly Detector - Identifies connections from suspicious geographic locations.
    
    Detects potential compromised accounts and unauthorized access by flagging
    connections from unexpected countries, high-risk regions, or impossible travel
    scenarios (same account from different countries in short timeframes).
    """
    
    MIN_ANOMALY_SCORE = 50
    # High-risk country codes (simplified list - real implementation would be more comprehensive)
    HIGH_RISK_COUNTRIES = ['CN', 'RU', 'KP', 'IR', 'SY', 'XX']  # XX = Unknown/Anonymous
    # Time window for impossible travel detection (hours)
    IMPOSSIBLE_TRAVEL_HOURS = 2
    
    def _get_name(self) -> str:
        return "Geo-Anomaly Detector (Suspicious Locations)"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'country_code']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze geographic patterns to detect anomalies.
        
        Args:
            df: DataFrame with connection logs including geographic data
            col_map: Mapping of column names. Optional 'timestamp' for impossible travel detection
        
        Returns:
            DataFrame with suspicious geographic activity
        """
        src_col = col_map['source_ip']
        country_col = col_map['country_code']
        
        df = df.copy()
        df[country_col] = df[country_col].fillna('XX').astype(str).str.upper()
        
        # Check if timestamp is available for impossible travel detection
        has_timestamp = 'timestamp' in col_map and col_map['timestamp'] in df.columns
        if has_timestamp:
            ts_col = col_map['timestamp']
            df[ts_col] = pd.to_datetime(df[ts_col])
        
        results = []
        
        # Group by source IP
        for src_ip, group in df.groupby(src_col):
            unique_countries = group[country_col].nunique()
            total_connections = len(group)
            countries_list = group[country_col].unique().tolist()
            
            # Calculate geo anomaly score (0-100)
            geo_score = 0.0
            flags = []
            
            # Factor 1: High-risk countries (40 points)
            high_risk_countries_found = [c for c in countries_list if c in self.HIGH_RISK_COUNTRIES]
            if high_risk_countries_found:
                geo_score += 40
                flags.append(f"High-risk countries: {', '.join(high_risk_countries_found)}")
            
            # Factor 2: Multiple countries (30 points)
            # Accessing from multiple countries is suspicious
            if unique_countries >= 5:
                geo_score += 30
                flags.append(f"{unique_countries} different countries")
            elif unique_countries >= 3:
                geo_score += 20
                flags.append(f"{unique_countries} different countries")
            elif unique_countries >= 2:
                geo_score += 10
                flags.append(f"{unique_countries} different countries")
            
            # Factor 3: Rapid country switching (30 points if timestamp available)
            if has_timestamp and unique_countries >= 2:
                # Sort by time and check for rapid country changes
                group_sorted = group.sort_values(ts_col)
                prev_country = None
                prev_time = None
                rapid_switches = 0
                
                for _, row in group_sorted.iterrows():
                    curr_country = row[country_col]
                    curr_time = row[ts_col]
                    
                    if prev_country is not None and prev_country != curr_country:
                        time_diff = (curr_time - prev_time).total_seconds() / 3600  # hours
                        if time_diff < self.IMPOSSIBLE_TRAVEL_HOURS:
                            rapid_switches += 1
                    
                    prev_country = curr_country
                    prev_time = curr_time
                
                if rapid_switches >= 3:
                    geo_score += 30
                    flags.append(f"Impossible travel: {rapid_switches} rapid country switches")
                elif rapid_switches >= 1:
                    geo_score += 15
                    flags.append(f"Suspicious travel: {rapid_switches} rapid country switches")
            
            # Only include if score meets threshold
            if geo_score >= self.MIN_ANOMALY_SCORE:
                results.append({
                    'source_ip': src_ip,
                    'unique_countries': unique_countries,
                    'countries': ', '.join(countries_list),
                    'total_connections': total_connections,
                    'high_risk_countries': ', '.join(high_risk_countries_found) if high_risk_countries_found else 'None',
                    'flags': ' | '.join(flags),
                    'geo_anomaly_score': min(geo_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('geo_anomaly_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate geo-anomaly visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['unique_countries'],
            y=result_df['geo_anomaly_score'],
            mode='markers',
            marker=dict(
                size=10,
                color=result_df['geo_anomaly_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Geo<br>Anomaly<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Countries: {result_df.iloc[i]['unique_countries']}<br>Flags: {result_df.iloc[i]['flags']}<br>Score: {result_df.iloc[i]['geo_anomaly_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Geo-Anomaly Detection: Country Diversity vs Suspicion Score",
            xaxis_title="Unique Countries",
            yaxis_title="Geo-Anomaly Score (0-100)",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for GeoAnomalyStrategy output columns."""
        return {
            'source_ip': 'The IP address with suspicious geographic patterns',
            'unique_countries': 'Number of different countries this IP has connected from',
            'countries': 'List of all countries detected for this IP',
            'total_connections': 'Total number of connections observed',
            'high_risk_countries': 'Any high-risk countries detected (CN, RU, KP, IR, etc.)',
            'flags': 'Specific anomalies detected (rapid country switching, impossible travel, etc.)',
            'geo_anomaly_score': 'Overall geographic anomaly score (0-100). Higher scores indicate suspicious location patterns such as connections from high-risk countries, impossible travel scenarios, or compromised accounts being accessed from multiple geographic locations. Scores ≥50 suggest potential account compromise or VPN/proxy abuse'
        }


class UserAgentAnomalyStrategy(HuntStrategy):
    """
    User-Agent Anomaly Detector - Identifies suspicious user agents.
    
    Detects automated tools, malicious bots, and suspicious user agent patterns
    that may indicate scanning, scraping, or attack activity.
    """
    
    MIN_ANOMALY_SCORE = 50
    # Common attack tools and scanners
    ATTACK_TOOL_SIGNATURES = [
        'sqlmap', 'nmap', 'nikto', 'masscan', 'nessus', 'burp', 'metasploit',
        'acunetix', 'appscan', 'w3af', 'skipfish', 'wpscan', 'havij', 'pangolin'
    ]
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = [
        'python', 'curl', 'wget', 'libwww', 'bot', 'crawler', 'spider',
        'scraper', 'scan', 'test', 'benchmark', 'load', 'stress'
    ]
    
    def _get_name(self) -> str:
        return "User-Agent Anomaly Detector (Bot & Attack Detection)"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'user_agent']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze user agent strings to detect anomalies.
        
        Args:
            df: DataFrame with HTTP logs including user agent strings
            col_map: Mapping of column names
        
        Returns:
            DataFrame with suspicious user agent activity
        """
        src_col = col_map['source_ip']
        ua_col = col_map['user_agent']
        
        df = df.copy()
        df[ua_col] = df[ua_col].fillna('').astype(str)
        
        results = []
        
        # Group by source IP
        for src_ip, group in df.groupby(src_col):
            unique_agents = group[ua_col].nunique()
            total_requests = len(group)
            
            # Analyze user agents
            attack_tools_found = []
            suspicious_agents = []
            empty_agents = 0
            very_short_agents = 0
            
            for ua in group[ua_col].unique():
                ua_lower = ua.lower()
                
                # Check for empty or very short user agents
                if len(ua) == 0:
                    empty_agents += 1
                    continue
                elif len(ua) < 10:
                    very_short_agents += 1
                
                # Check for attack tools
                for tool in self.ATTACK_TOOL_SIGNATURES:
                    if tool in ua_lower:
                        attack_tools_found.append(tool)
                        break
                
                # Check for suspicious patterns
                for pattern in self.SUSPICIOUS_PATTERNS:
                    if pattern in ua_lower:
                        suspicious_agents.append(ua[:50])  # Truncate for display
                        break
            
            # Calculate anomaly score (0-100)
            ua_score = 0.0
            flags = []
            
            # Factor 1: Attack tools detected (50 points - immediate red flag)
            if attack_tools_found:
                ua_score += 50
                flags.append(f"Attack tools: {', '.join(set(attack_tools_found))}")
            
            # Factor 2: Suspicious patterns (30 points)
            if len(suspicious_agents) > 0:
                ua_score += 30
                flags.append(f"{len(suspicious_agents)} suspicious user agents")
            
            # Factor 3: Empty or malformed user agents (20 points)
            if empty_agents > 0:
                ua_score += 20
                flags.append(f"{empty_agents} empty user agents")
            elif very_short_agents >= 3:
                ua_score += 15
                flags.append(f"{very_short_agents} suspiciously short user agents")
            
            # Factor 4: Too many different user agents (bonus 10 points)
            # Legitimate users typically have 1-3 user agents
            if unique_agents >= 10:
                ua_score += 10
                flags.append(f"{unique_agents} different user agents")
            
            # Only include if score meets threshold
            if ua_score >= self.MIN_ANOMALY_SCORE:
                # Get sample of suspicious user agents
                sample_agents = list(set(suspicious_agents + [ua[:50] for ua in group[ua_col].head(3) if ua]))[:3]
                
                results.append({
                    'source_ip': src_ip,
                    'unique_user_agents': unique_agents,
                    'total_requests': total_requests,
                    'attack_tools_detected': ', '.join(set(attack_tools_found)) if attack_tools_found else 'None',
                    'suspicious_count': len(suspicious_agents),
                    'empty_agents': empty_agents,
                    'sample_agents': ' | '.join(sample_agents),
                    'flags': ' | '.join(flags),
                    'ua_anomaly_score': min(ua_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('ua_anomaly_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate user agent anomaly visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['total_requests'],
            y=result_df['unique_user_agents'],
            mode='markers',
            marker=dict(
                size=10,
                color=result_df['ua_anomaly_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="UA<br>Anomaly<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Requests: {result_df.iloc[i]['total_requests']}<br>Unique UAs: {result_df.iloc[i]['unique_user_agents']}<br>Flags: {result_df.iloc[i]['flags']}<br>Score: {result_df.iloc[i]['ua_anomaly_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="User-Agent Anomaly Detection: Request Volume vs UA Diversity",
            xaxis_title="Total Requests",
            yaxis_title="Unique User Agents",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for UserAgentAnomalyStrategy output columns."""
        return {
            'source_ip': 'The IP address with suspicious user agent patterns',
            'unique_user_agents': 'Number of different user agent strings used. Normal users typically have 1-3; high values suggest automated tools or scanning',
            'total_requests': 'Total number of HTTP requests observed',
            'attack_tools_detected': 'Specific attack tools identified in user agents (sqlmap, nmap, nikto, etc.)',
            'suspicious_count': 'Number of suspicious user agent strings detected',
            'empty_agents': 'Number of requests with empty/missing user agent strings, often indicating automated tools',
            'sample_agents': 'Sample of suspicious user agent strings found',
            'flags': 'Specific anomalies detected in user agent patterns',
            'ua_anomaly_score': 'Overall user agent anomaly score (0-100). Higher scores indicate automated scanning tools, malicious bots, or attack frameworks. Scores ≥50 strongly suggest reconnaissance or attack activity requiring immediate investigation'
        }


class CryptoMiningStrategy(HuntStrategy):
    """
    Crypto Mining Detector - Identifies cryptocurrency mining activity.
    
    Detects potential cryptojacking and unauthorized cryptocurrency mining by
    analyzing network traffic patterns, connection destinations, and resource usage
    indicators typical of mining operations.
    """
    
    MIN_MINING_SCORE = 50
    # Known mining pool domains and IPs (simplified - real list would be much larger)
    MINING_POOL_PATTERNS = [
        'pool', 'stratum', 'mining', 'minergate', 'nicehash', 'nanopool',
        'ethermine', 'sparkpool', 'f2pool', 'antpool', 'slushpool', 'coinhive'
    ]
    # Common mining ports
    MINING_PORTS = [3333, 4444, 5555, 7777, 8888, 9332, 9999, 14433, 14444, 45560]
    # Minimum connections for detection
    MIN_CONNECTIONS = 10
    
    def _get_name(self) -> str:
        return "Crypto Mining Detector (Cryptojacking)"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'dest_ip', 'dest_port']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze traffic patterns to detect cryptocurrency mining.
        
        Args:
            df: DataFrame with connection logs
            col_map: Mapping of column names. Optional 'dest_domain' for domain analysis
        
        Returns:
            DataFrame with suspicious mining activity
        """
        src_col = col_map['source_ip']
        dst_col = col_map['dest_ip']
        port_col = col_map['dest_port']
        
        df = df.copy()
        df[port_col] = pd.to_numeric(df[port_col], errors='coerce')
        df = df.dropna(subset=[port_col])
        
        # Check if domain column is available
        has_domain = 'dest_domain' in col_map and col_map['dest_domain'] in df.columns
        if has_domain:
            domain_col = col_map['dest_domain']
            df[domain_col] = df[domain_col].fillna('').astype(str).str.lower()
        
        results = []
        
        # Group by source IP
        for src_ip, group in df.groupby(src_col):
            total_connections = len(group)
            
            # Need minimum connections for meaningful analysis
            if total_connections < self.MIN_CONNECTIONS:
                continue
            
            unique_dests = group[dst_col].nunique()
            ports_used = group[port_col].unique().tolist()
            
            # Calculate mining score (0-100)
            mining_score = 0.0
            flags = []
            mining_pool_matches = []
            
            # Factor 1: Known mining ports (40 points)
            mining_ports_found = [p for p in ports_used if p in self.MINING_PORTS]
            if mining_ports_found:
                mining_score += 40
                flags.append(f"Mining ports: {', '.join(map(str, mining_ports_found))}")
            
            # Factor 2: Domain patterns (30 points if domain available)
            if has_domain:
                for domain in group[domain_col].unique():
                    for pattern in self.MINING_POOL_PATTERNS:
                        if pattern in domain:
                            mining_pool_matches.append(domain)
                            break
                
                if mining_pool_matches:
                    mining_score += 30
                    flags.append(f"Mining pool domains: {len(mining_pool_matches)} found")
            
            # Factor 3: Long-lived connections to few destinations (20 points)
            # Mining maintains persistent connections
            if unique_dests <= 5 and total_connections >= 50:
                mining_score += 20
                flags.append(f"Persistent connections: {total_connections} to {unique_dests} destinations")
            elif unique_dests <= 10 and total_connections >= 100:
                mining_score += 15
                flags.append("Many connections to few destinations")
            
            # Factor 4: Regular connection patterns (10 points)
            # Check if connections are evenly distributed (consistent timing)
            if unique_dests > 0:
                connections_per_dest = total_connections / unique_dests
                if connections_per_dest >= 20:
                    mining_score += 10
                    flags.append(f"Regular pattern: {connections_per_dest:.1f} connections per destination")
            
            # Only include if score meets threshold
            if mining_score >= self.MIN_MINING_SCORE:
                results.append({
                    'source_ip': src_ip,
                    'total_connections': total_connections,
                    'unique_destinations': unique_dests,
                    'mining_ports_used': ', '.join(map(str, mining_ports_found)) if mining_ports_found else 'None',
                    'mining_pool_matches': ', '.join(mining_pool_matches[:3]) if mining_pool_matches else 'None',
                    'flags': ' | '.join(flags),
                    'mining_score': min(mining_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('mining_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate crypto mining visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['total_connections'],
            y=result_df['unique_destinations'],
            mode='markers',
            marker=dict(
                size=10,
                color=result_df['mining_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Mining<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Connections: {result_df.iloc[i]['total_connections']}<br>Destinations: {result_df.iloc[i]['unique_destinations']}<br>Flags: {result_df.iloc[i]['flags']}<br>Score: {result_df.iloc[i]['mining_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Crypto Mining Detection: Connection Volume vs Destination Diversity",
            xaxis_title="Total Connections",
            yaxis_title="Unique Destinations",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for CryptoMiningStrategy output columns."""
        return {
            'source_ip': 'The IP address potentially engaged in cryptocurrency mining',
            'total_connections': 'Total number of connections observed',
            'unique_destinations': 'Number of different destination IPs contacted. Mining typically maintains connections to few mining pools',
            'mining_ports_used': 'Known cryptocurrency mining ports detected (3333, 4444, etc.)',
            'mining_pool_matches': 'Mining pool domains or patterns identified in connection destinations',
            'flags': 'Specific mining indicators detected',
            'mining_score': 'Overall cryptocurrency mining suspiciousness score (0-100). Higher scores indicate likely cryptojacking or unauthorized mining activity. Scores ≥50 suggest active mining operations that consume resources and may indicate malware infection or policy violations'
        }


class DNSAnomalyStrategy(HuntStrategy):
    """
    Detects suspicious DNS query patterns that may indicate malware, data exfiltration,
    or reconnaissance activities. Analyzes DNS queries for:
    - Unusually high query volumes
    - Rare or suspicious TLDs
    - Typosquatting attempts
    - Long subdomain chains (potential DGA domains)
    - Excessive NXDOMAIN responses
    """
    
    def _get_name(self) -> str:
        return "DNS Anomaly Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'query_name', 'response_code']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze DNS queries for suspicious patterns.
        
        Args:
            df: DataFrame with DNS query logs
            col_map: Column mapping
        
        Returns:
            DataFrame with DNS anomaly results
        """
        if df.empty:
            return pd.DataFrame()
        
        # Map columns
        src_col = col_map['source_ip']
        query_col = col_map['query_name']
        resp_col = col_map['response_code']
        
        # Suspicious TLDs commonly used by malware
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc', '.ws', '.top', '.xyz']
        
        # Calculate DNS metrics per source IP
        results = []
        
        for src_ip, group in df.groupby(src_col):
            total_queries = len(group)
            
            if total_queries < 5:  # Skip low-volume sources
                continue
            
            # Extract query names
            queries = group[query_col].astype(str).tolist()
            
            # Analyze query patterns
            unique_domains = len(set(queries))
            avg_query_length = np.mean([len(q) for q in queries])
            max_query_length = max([len(q) for q in queries])
            
            # Count suspicious TLD usage
            suspicious_tld_count = sum(1 for q in queries if any(q.endswith(tld) for tld in suspicious_tlds))
            
            # Count NXDOMAIN responses (typically response code 3)
            nxdomain_count = len(group[group[resp_col].astype(str).str.contains('3|NXDOMAIN', na=False, case=False)])
            nxdomain_ratio = nxdomain_count / total_queries if total_queries > 0 else 0
            
            # Count long subdomain chains (potential DGA)
            long_subdomain_count = sum(1 for q in queries if q.count('.') > 3)
            
            # Count queries with high entropy subdomains (randomness)
            high_entropy_queries = 0
            for q in queries:
                # Calculate entropy of the first part of the domain
                subdomain = q.split('.')[0] if '.' in q else q
                subdomain_len = len(subdomain)
                if subdomain_len > 5:
                    # Simple entropy calculation
                    char_counts = {}
                    for char in subdomain:
                        char_counts[char] = char_counts.get(char, 0) + 1
                    entropy_val = -sum((count/subdomain_len) * np.log2(count/subdomain_len) 
                                      for count in char_counts.values())
                    if entropy_val > 3.5:  # High randomness threshold
                        high_entropy_queries += 1
            
            # Calculate anomaly score
            dns_score = 0
            flags = []
            
            # High volume scoring
            if total_queries > 100:
                dns_score += 25
                flags.append(f'HIGH_VOLUME({total_queries})')
            elif total_queries > 50:
                dns_score += 15
                flags.append(f'ELEVATED_VOLUME({total_queries})')
            
            # Suspicious TLD scoring
            if suspicious_tld_count > 0:
                tld_ratio = suspicious_tld_count / total_queries
                dns_score += min(30, int(tld_ratio * 100))
                flags.append(f'SUSPICIOUS_TLD({suspicious_tld_count})')
            
            # NXDOMAIN ratio scoring (high failure rate suspicious)
            if nxdomain_ratio > 0.5:
                dns_score += 20
                flags.append(f'HIGH_NXDOMAIN({nxdomain_count})')
            elif nxdomain_ratio > 0.3:
                dns_score += 10
                flags.append('ELEVATED_NXDOMAIN')
            
            # Long query scoring
            if avg_query_length > 50:
                dns_score += 15
                flags.append(f'LONG_QUERIES(avg:{int(avg_query_length)})')
            
            # DGA-like subdomain chains
            if long_subdomain_count > total_queries * 0.3:
                dns_score += 20
                flags.append(f'DGA_PATTERN({long_subdomain_count})')
            
            # High entropy queries
            if high_entropy_queries > total_queries * 0.3:
                dns_score += 25
                flags.append(f'HIGH_ENTROPY({high_entropy_queries})')
            
            # Only report if score is meaningful
            if dns_score >= 30 or len(flags) > 0:
                results.append({
                    'source_ip': src_ip,
                    'total_queries': total_queries,
                    'unique_domains': unique_domains,
                    'avg_query_length': round(avg_query_length, 1),
                    'max_query_length': max_query_length,
                    'suspicious_tld_count': suspicious_tld_count,
                    'nxdomain_count': nxdomain_count,
                    'nxdomain_ratio': round(nxdomain_ratio, 2),
                    'high_entropy_queries': high_entropy_queries,
                    'flags': ' | '.join(flags) if flags else 'ANOMALOUS_PATTERN',
                    'dns_anomaly_score': min(dns_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('dns_anomaly_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate DNS anomaly visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['total_queries'],
            y=result_df['nxdomain_ratio'],
            mode='markers',
            marker=dict(
                size=result_df['high_entropy_queries'] / 2,
                color=result_df['dns_anomaly_score'],
                colorscale='YlOrRd',
                showscale=True,
                colorbar=dict(title="DNS<br>Anomaly<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Queries: {result_df.iloc[i]['total_queries']}<br>NXDOMAIN: {result_df.iloc[i]['nxdomain_ratio']:.1%}<br>Flags: {result_df.iloc[i]['flags']}<br>Score: {result_df.iloc[i]['dns_anomaly_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="DNS Anomaly Detection: Query Volume vs Failure Rate",
            xaxis_title="Total DNS Queries",
            yaxis_title="NXDOMAIN Ratio (Failure Rate)",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for DNSAnomalyStrategy output columns."""
        return {
            'source_ip': 'The IP address making suspicious DNS queries',
            'total_queries': 'Total number of DNS queries made by this source',
            'unique_domains': 'Number of different domain names queried',
            'avg_query_length': 'Average length of query strings. Longer queries may indicate data exfiltration via DNS tunneling',
            'max_query_length': 'Longest query string observed. Extremely long queries are suspicious',
            'suspicious_tld_count': 'Count of queries to high-risk TLDs (.tk, .ml, .ga, etc.) commonly used by malware',
            'nxdomain_count': 'Number of failed DNS lookups (domain not found)',
            'nxdomain_ratio': 'Percentage of queries that failed. High ratios may indicate DGA malware or reconnaissance',
            'high_entropy_queries': 'Count of queries with random-looking subdomains, typical of DGA (Domain Generation Algorithm) malware',
            'flags': 'Specific DNS anomaly indicators detected',
            'dns_anomaly_score': 'Overall DNS anomaly suspiciousness score (0-100). Higher scores indicate likely malware C2 communication, DNS tunneling, or reconnaissance. Scores ≥50 warrant investigation for DGA malware, data exfiltration, or other DNS-based attacks'
        }


class AccountTakeoverStrategy(HuntStrategy):
    """
    Detects account takeover and credential theft patterns by analyzing:
    - Rapid role or privilege changes
    - Impossible travel scenarios (location switches)
    - Unusual access patterns and times
    - Multiple failed login attempts followed by success
    - Access from new devices or locations
    """
    
    def _get_name(self) -> str:
        return "Account Takeover Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'username', 'source_ip', 'action', 'status']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze authentication and access patterns for account takeover indicators.
        
        Args:
            df: DataFrame with authentication/access logs
            col_map: Column mapping
        
        Returns:
            DataFrame with account takeover detection results
        """
        if df.empty:
            return pd.DataFrame()
        
        # Map columns
        ts_col = col_map['timestamp']
        user_col = col_map['username']
        ip_col = col_map['source_ip']
        status_col = col_map['status']
        
        # Convert timestamp to datetime if needed
        if not pd.api.types.is_datetime64_any_dtype(df[ts_col]):
            df[ts_col] = pd.to_datetime(df[ts_col], errors='coerce')
        
        # Sort by user and time
        df = df.sort_values([user_col, ts_col])
        
        results = []
        
        for username, group in df.groupby(user_col):
            if len(group) < 3:  # Need enough activity to analyze
                continue
            
            # Extract data
            timestamps = group[ts_col].tolist()
            ips = group[ip_col].astype(str).tolist()
            statuses = group[status_col].astype(str).tolist()
            
            # Calculate metrics
            total_events = len(group)
            unique_ips = len(set(ips))
            
            # Count failed attempts
            failed_attempts = sum(1 for s in statuses 
                                 if 'fail' in str(s).lower() or 'denied' in str(s).lower() 
                                 or '401' in str(s) or '403' in str(s))
            
            # Calculate failure rate
            failure_rate = failed_attempts / total_events if total_events > 0 else 0
            
            # Check for rapid IP switching (potential credential stuffing)
            rapid_ip_switches = 0
            for i in range(1, len(timestamps)):
                time_diff = (timestamps[i] - timestamps[i-1]).total_seconds()
                if time_diff < 60 and ips[i] != ips[i-1]:  # Different IP within 1 minute
                    rapid_ip_switches += 1
            
            # Check for failed login followed by success from different IP
            compromised_pattern = False
            for i in range(1, len(statuses)):
                prev_status = str(statuses[i-1]).lower()
                curr_status = str(statuses[i]).lower()
                if ('fail' in prev_status or 'denied' in prev_status) and \
                   ('success' in curr_status or 'ok' in curr_status) and \
                   ips[i] != ips[i-1]:
                    compromised_pattern = True
                    break
            
            # Check for unusual activity times (off-hours)
            off_hours_count = 0
            for ts in timestamps:
                hour = ts.hour
                weekday = ts.weekday()
                # Off-hours: before 6 AM, after 8 PM, or weekends
                if hour < 6 or hour > 20 or weekday >= 5:
                    off_hours_count += 1
            
            off_hours_ratio = off_hours_count / total_events if total_events > 0 else 0
            
            # Calculate takeover score
            takeover_score = 0
            flags = []
            
            # Multiple IPs scoring
            if unique_ips >= 5:
                takeover_score += 30
                flags.append(f'MULTI_IP({unique_ips})')
            elif unique_ips >= 3:
                takeover_score += 15
                flags.append(f'MULTIPLE_IPS({unique_ips})')
            
            # Rapid IP switching scoring
            if rapid_ip_switches > 0:
                takeover_score += min(25, rapid_ip_switches * 5)
                flags.append(f'RAPID_IP_SWITCH({rapid_ip_switches})')
            
            # High failure rate scoring
            if failure_rate > 0.5:
                takeover_score += 25
                flags.append(f'HIGH_FAIL_RATE({failed_attempts})')
            elif failure_rate > 0.3:
                takeover_score += 15
                flags.append('ELEVATED_FAILURES')
            
            # Compromised pattern (failed then success from different IP)
            if compromised_pattern:
                takeover_score += 30
                flags.append('COMPROMISED_PATTERN')
            
            # Off-hours activity
            if off_hours_ratio > 0.7:
                takeover_score += 20
                flags.append(f'OFF_HOURS({off_hours_count})')
            elif off_hours_ratio > 0.5:
                takeover_score += 10
                flags.append('ELEVATED_OFF_HOURS')
            
            # Only report if score is meaningful
            if takeover_score >= 35 or len(flags) > 0:
                results.append({
                    'username': username,
                    'total_events': total_events,
                    'unique_ips': unique_ips,
                    'failed_attempts': failed_attempts,
                    'failure_rate': round(failure_rate, 2),
                    'rapid_ip_switches': rapid_ip_switches,
                    'off_hours_events': off_hours_count,
                    'off_hours_ratio': round(off_hours_ratio, 2),
                    'compromised_pattern': 'YES' if compromised_pattern else 'NO',
                    'flags': ' | '.join(flags) if flags else 'SUSPICIOUS_PATTERN',
                    'takeover_score': min(takeover_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('takeover_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate account takeover visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['unique_ips'],
            y=result_df['failure_rate'],
            mode='markers',
            marker=dict(
                size=result_df['rapid_ip_switches'] * 2 + 8,
                color=result_df['takeover_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Takeover<br>Score")
            ),
            text=[f"User: {result_df.iloc[i]['username']}<br>IPs: {result_df.iloc[i]['unique_ips']}<br>Failure Rate: {result_df.iloc[i]['failure_rate']:.1%}<br>Flags: {result_df.iloc[i]['flags']}<br>Score: {result_df.iloc[i]['takeover_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Account Takeover Detection: IP Diversity vs Authentication Failures",
            xaxis_title="Number of Unique IPs",
            yaxis_title="Authentication Failure Rate",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for AccountTakeoverStrategy output columns."""
        return {
            'username': 'The user account showing suspicious activity patterns',
            'total_events': 'Total number of authentication/access events for this account',
            'unique_ips': 'Number of different source IPs used. High values suggest credential sharing or compromise',
            'failed_attempts': 'Number of failed authentication attempts',
            'failure_rate': 'Percentage of failed authentication attempts. High rates suggest brute force or credential stuffing',
            'rapid_ip_switches': 'Count of IP address changes within 1-minute windows, indicating possible credential stuffing attacks',
            'off_hours_events': 'Number of access events outside normal business hours (before 6 AM, after 8 PM, or weekends)',
            'off_hours_ratio': 'Percentage of events occurring off-hours. High ratios suggest unauthorized access',
            'compromised_pattern': 'Whether failed login followed by success from different IP was detected (strong indicator of compromise)',
            'flags': 'Specific account takeover indicators detected',
            'takeover_score': 'Overall account takeover suspiciousness score (0-100). Higher scores indicate likely credential theft, account compromise, or credential stuffing attacks. Scores ≥50 warrant immediate investigation and potentially disabling the account'
        }


class DataStagingStrategy(HuntStrategy):
    """
    Detects data staging activities that often precede exfiltration by analyzing:
    - Files being compressed or archived
    - Large file operations
    - Access to sensitive directories
    - Rapid sequential file access patterns
    - Creation of temporary staging locations
    """
    
    def _get_name(self) -> str:
        return "Data Staging Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'file_path', 'operation', 'file_size']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze file operations for data staging patterns.
        
        Args:
            df: DataFrame with file operation logs
            col_map: Column mapping
        
        Returns:
            DataFrame with data staging detection results
        """
        if df.empty:
            return pd.DataFrame()
        
        # Map columns
        ts_col = col_map['timestamp']
        src_col = col_map['source_ip']
        path_col = col_map['file_path']
        op_col = col_map['operation']
        size_col = col_map['file_size']
        
        # Convert timestamp to datetime if needed
        if not pd.api.types.is_datetime64_any_dtype(df[ts_col]):
            df[ts_col] = pd.to_datetime(df[ts_col], errors='coerce')
        
        # Convert file size to numeric if needed
        if not pd.api.types.is_numeric_dtype(df[size_col]):
            df[size_col] = pd.to_numeric(df[size_col], errors='coerce')
        
        # Fill NaN sizes with 0
        df[size_col] = df[size_col].fillna(0)
        
        # Suspicious file extensions for staging/compression
        staging_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.tmp', '.staging']
        
        # Sensitive directory patterns
        sensitive_patterns = ['finance', 'payroll', 'hr', 'employee', 'customer', 'confidential', 
                             'secret', 'password', 'credential', 'backup', 'database', 'db']
        
        results = []
        
        for src_ip, group in df.groupby(src_col):
            if len(group) < 5:  # Need enough activity to analyze
                continue
            
            # Extract data
            file_paths = group[path_col].astype(str).tolist()
            operations = group[op_col].astype(str).tolist()
            file_sizes = group[size_col].tolist()
            timestamps = group[ts_col].tolist()
            
            # Calculate metrics
            total_operations = len(group)
            unique_files = len(set(file_paths))
            total_size_mb = sum(file_sizes) / (1024 * 1024)  # Convert to MB
            
            # Count staging file operations
            staging_ops = sum(1 for path in file_paths 
                             if any(path.lower().endswith(ext) for ext in staging_extensions))
            
            # Count access to sensitive directories
            sensitive_access = sum(1 for path in file_paths 
                                   if any(pattern in path.lower() for pattern in sensitive_patterns))
            
            # Count large file operations (>10 MB)
            large_file_ops = sum(1 for size in file_sizes if size > 10 * 1024 * 1024)
            
            # Check for rapid sequential access (potential bulk collection)
            rapid_operations = 0
            for i in range(1, len(timestamps)):
                time_diff = (timestamps[i] - timestamps[i-1]).total_seconds()
                if time_diff < 5:  # Operations within 5 seconds
                    rapid_operations += 1
            
            # Count write/create operations (staging activity)
            write_ops = sum(1 for op in operations 
                           if 'write' in str(op).lower() or 'create' in str(op).lower() 
                           or 'copy' in str(op).lower())
            
            # Calculate average file size
            avg_file_size_mb = total_size_mb / total_operations if total_operations > 0 else 0
            
            # Calculate staging score
            staging_score = 0
            flags = []
            
            # High volume scoring
            if total_operations > 100:
                staging_score += 20
                flags.append(f'HIGH_VOLUME({total_operations})')
            elif total_operations > 50:
                staging_score += 10
                flags.append('ELEVATED_VOLUME')
            
            # Staging file operations scoring
            if staging_ops > 0:
                staging_ratio = staging_ops / total_operations
                staging_score += min(30, int(staging_ratio * 100))
                flags.append(f'STAGING_FILES({staging_ops})')
            
            # Sensitive directory access scoring
            if sensitive_access > 0:
                sensitive_ratio = sensitive_access / total_operations
                staging_score += min(25, int(sensitive_ratio * 100))
                flags.append(f'SENSITIVE_ACCESS({sensitive_access})')
            
            # Large file operations scoring
            if large_file_ops > 0:
                staging_score += min(20, large_file_ops * 5)
                flags.append(f'LARGE_FILES({large_file_ops})')
            
            # Total size scoring
            if total_size_mb > 500:
                staging_score += 20
                flags.append(f'MASSIVE_VOLUME({int(total_size_mb)}MB)')
            elif total_size_mb > 100:
                staging_score += 10
                flags.append(f'HIGH_VOLUME({int(total_size_mb)}MB)')
            
            # Rapid operations scoring
            if rapid_operations > total_operations * 0.5:
                staging_score += 15
                flags.append(f'RAPID_OPS({rapid_operations})')
            
            # Write operations scoring
            write_ratio = write_ops / total_operations if total_operations > 0 else 0
            if write_ratio > 0.7:
                staging_score += 15
                flags.append(f'HIGH_WRITE_ACTIVITY({write_ops})')
            
            # Only report if score is meaningful
            if staging_score >= 35 or len(flags) > 0:
                results.append({
                    'source_ip': src_ip,
                    'total_operations': total_operations,
                    'unique_files': unique_files,
                    'total_size_mb': round(total_size_mb, 1),
                    'avg_file_size_mb': round(avg_file_size_mb, 1),
                    'staging_file_ops': staging_ops,
                    'sensitive_access': sensitive_access,
                    'large_file_ops': large_file_ops,
                    'rapid_operations': rapid_operations,
                    'write_operations': write_ops,
                    'flags': ' | '.join(flags) if flags else 'STAGING_PATTERN',
                    'staging_score': min(staging_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('staging_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate data staging visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['total_operations'],
            y=result_df['total_size_mb'],
            mode='markers',
            marker=dict(
                size=result_df['sensitive_access'] * 2 + 8,
                color=result_df['staging_score'],
                colorscale='OrRd',
                showscale=True,
                colorbar=dict(title="Staging<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Operations: {result_df.iloc[i]['total_operations']}<br>Total Size: {result_df.iloc[i]['total_size_mb']:.1f}MB<br>Flags: {result_df.iloc[i]['flags']}<br>Score: {result_df.iloc[i]['staging_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Data Staging Detection: Operation Volume vs Data Size",
            xaxis_title="Total File Operations",
            yaxis_title="Total Data Size (MB)",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for DataStagingStrategy output columns."""
        return {
            'source_ip': 'The IP address performing suspicious file operations',
            'total_operations': 'Total number of file operations performed',
            'unique_files': 'Number of different files accessed or modified',
            'total_size_mb': 'Total volume of data accessed in megabytes. Large volumes suggest bulk data collection',
            'avg_file_size_mb': 'Average file size accessed. Helps identify bulk operations vs many small files',
            'staging_file_ops': 'Number of operations on staging/compression files (.zip, .rar, .tmp, etc.)',
            'sensitive_access': 'Count of accesses to sensitive directories (finance, HR, customer data, etc.)',
            'large_file_ops': 'Number of operations on large files (>10 MB)',
            'rapid_operations': 'Count of operations within 5-second windows, indicating automated bulk collection',
            'write_operations': 'Number of write/create/copy operations, indicating data is being staged rather than just read',
            'flags': 'Specific data staging indicators detected',
            'staging_score': 'Overall data staging suspiciousness score (0-100). Higher scores indicate likely preparation for data exfiltration. Scores ≥50 suggest an insider threat or compromised account collecting data before exfiltration. Immediate investigation recommended'
        }


class FilelessMalwareStrategy(HuntStrategy):
    """
    Fileless Malware Detector - Identifies memory-resident attacks and living-off-the-land techniques.
    
    Detects PowerShell abuse, WMI execution, suspicious script activity, and use of
    legitimate system tools for malicious purposes (LOLBins). Critical for detecting
    modern attacks that avoid writing files to disk.
    """
    
    MIN_FILELESS_SCORE = 50
    # Suspicious processes and commands commonly used in fileless attacks
    SUSPICIOUS_PROCESSES = [
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
        'regsvr32.exe', 'rundll32.exe', 'wmic.exe', 'certutil.exe', 'bitsadmin.exe',
        'psexec.exe', 'wmiprvse.exe', 'schtasks.exe', 'at.exe', 'sc.exe'
    ]
    SUSPICIOUS_KEYWORDS = [
        'invoke-expression', 'iex', 'downloadstring', 'downloadfile', 'webclient',
        'net.webclient', 'bitstransfer', 'encoded', '-enc', '-e ', 'bypass',
        'hidden', 'noprofile', '-w hidden', 'reflection.assembly', 'mimikatz',
        'invoke-mimikatz', 'powersploit', 'empire', 'cobalt', 'metasploit'
    ]
    
    def _get_name(self) -> str:
        return "Fileless Malware Detector (LOLBins & Memory Attacks)"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'process_name', 'command_line']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze process execution logs to detect fileless malware patterns.
        
        Args:
            df: DataFrame with process execution logs
            col_map: Column mapping including source_ip, process_name, command_line
        
        Returns:
            DataFrame with suspicious fileless attack indicators
        """
        src_col = col_map['source_ip']
        proc_col = col_map['process_name']
        cmd_col = col_map['command_line']
        
        df = df.copy()
        df[proc_col] = df[proc_col].fillna('').astype(str).str.lower()
        df[cmd_col] = df[cmd_col].fillna('').astype(str).str.lower()
        
        # Pre-compile regex for better performance
        encoded_pattern = re.compile(r'encoded|base64|-enc', re.IGNORECASE)
        
        results = []
        
        # Group by source IP
        for src_ip, group in df.groupby(src_col):
            total_events = len(group)
            
            if total_events < 5:  # Need minimum events for analysis
                continue
            
            fileless_score = 0.0
            flags = []
            suspicious_procs = set()
            keyword_matches = []
            
            # Factor 1: Suspicious process execution (30 points)
            for proc in self.SUSPICIOUS_PROCESSES:
                matching_events = group[group[proc_col].str.contains(proc, regex=False)]
                if not matching_events.empty:
                    suspicious_procs.add(proc)
                    fileless_score += min(len(matching_events) * 5, 30)  # Cap at 30
            
            if suspicious_procs:
                flags.append(f"Suspicious processes: {', '.join(list(suspicious_procs)[:3])}")
            
            # Factor 2: Malicious keywords in command lines (40 points)
            for keyword in self.SUSPICIOUS_KEYWORDS:
                matching_cmds = group[group[cmd_col].str.contains(keyword, regex=False, na=False)]
                if not matching_cmds.empty:
                    keyword_matches.append(keyword)
                    fileless_score += min(len(matching_cmds) * 8, 40)  # Cap at 40
            
            if keyword_matches:
                flags.append(f"Malicious keywords: {', '.join(keyword_matches[:3])}")
            
            # Factor 3: Encoded/obfuscated commands (20 points)
            encoded_count = group[group[cmd_col].str.contains(encoded_pattern, regex=True, na=False)].shape[0]
            if encoded_count > 0:
                fileless_score += min(encoded_count * 10, 20)
                flags.append(f"Encoded commands: {encoded_count}")
            
            # Factor 4: Multiple LOLBin usage (10 points)
            lolbins_used = len(suspicious_procs)
            if lolbins_used >= 3:
                fileless_score += 10
                flags.append(f"Multiple LOLBins: {lolbins_used}")
            
            # Only include if score meets threshold
            if fileless_score >= self.MIN_FILELESS_SCORE:
                results.append({
                    'source_ip': src_ip,
                    'total_events': total_events,
                    'suspicious_processes': ', '.join(list(suspicious_procs)[:5]) if suspicious_procs else 'None',
                    'suspicious_keywords': ', '.join(keyword_matches[:5]) if keyword_matches else 'None',
                    'encoded_commands': encoded_count,
                    'lolbins_count': lolbins_used,
                    'flags': ' | '.join(flags),
                    'fileless_score': min(fileless_score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('fileless_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate fileless malware visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['total_events'],
            y=result_df['lolbins_count'],
            mode='markers',
            marker=dict(
                size=result_df['encoded_commands'] * 3 + 10,
                color=result_df['fileless_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Fileless<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Events: {result_df.iloc[i]['total_events']}<br>LOLBins: {result_df.iloc[i]['lolbins_count']}<br>Encoded: {result_df.iloc[i]['encoded_commands']}<br>Score: {result_df.iloc[i]['fileless_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Fileless Malware Detection: Event Volume vs LOLBin Diversity",
            xaxis_title="Total Suspicious Events",
            yaxis_title="Number of Different LOLBins Used",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for FilelessMalwareStrategy output columns."""
        return {
            'source_ip': 'The IP address or host executing suspicious processes',
            'total_events': 'Total number of process execution events observed',
            'suspicious_processes': 'Living-off-the-land binaries (LOLBins) and attack tools detected (PowerShell, WMI, etc.)',
            'suspicious_keywords': 'Malicious keywords found in command lines (Invoke-Expression, downloadstring, bypass, etc.)',
            'encoded_commands': 'Number of encoded or obfuscated commands detected, often used to evade detection',
            'lolbins_count': 'Count of different LOLBins used. Multiple tools suggest sophisticated attack',
            'flags': 'Specific fileless attack indicators detected',
            'fileless_score': 'Overall fileless malware suspiciousness score (0-100). Higher scores indicate likely memory-resident malware or living-off-the-land attack techniques. Scores ≥50 suggest active fileless attack in progress. Immediate memory forensics and incident response recommended'
        }


class APIAbuseStrategy(HuntStrategy):
    """
    API Abuse Detector - Identifies excessive API usage, rate limit violations, and token abuse.
    
    Detects automated scraping, credential stuffing via APIs, token theft, and
    abnormal API consumption patterns that may indicate account compromise or
    malicious automation.
    """
    
    MIN_ABUSE_SCORE = 50
    # API-specific HTTP methods and patterns
    API_PATTERNS = ['/api/', '/v1/', '/v2/', '/v3/', '/rest/', '/graphql', '/oauth', '/token']
    HIGH_RATE_THRESHOLD = 100  # Requests per minute threshold
    
    def _get_name(self) -> str:
        return "API Abuse Detector (Scraping & Rate Limit Violations)"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'url_path', 'status_code']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze API access logs to detect abuse patterns.
        
        Args:
            df: DataFrame with API access logs
            col_map: Column mapping including source_ip, url_path, status_code
                     Optional: 'timestamp', 'user_agent', 'auth_token'
        
        Returns:
            DataFrame with suspicious API abuse patterns
        """
        src_col = col_map['source_ip']
        url_col = col_map['url_path']
        status_col = col_map['status_code']
        
        df = df.copy()
        df[url_col] = df[url_col].fillna('').astype(str).str.lower()
        df[status_col] = df[status_col].astype(str)
        
        # Check optional columns
        has_timestamp = 'timestamp' in col_map and col_map['timestamp'] in df.columns
        has_token = 'auth_token' in col_map and col_map['auth_token'] in df.columns
        
        if has_timestamp:
            ts_col = col_map['timestamp']
            df[ts_col] = pd.to_datetime(df[ts_col], errors='coerce')
            df = df.dropna(subset=[ts_col])
        
        # Pre-compile regex patterns for better performance
        rate_limit_pattern = re.compile(r'429|509')
        auth_failure_pattern = re.compile(r'401|403')
        
        results = []
        
        # Group by source IP
        for src_ip, group in df.groupby(src_col):
            total_requests = len(group)
            
            if total_requests < 20:  # Need minimum requests for analysis
                continue
            
            abuse_score = 0.0
            flags = []
            
            # Factor 1: High request volume (30 points)
            if total_requests >= 1000:
                abuse_score += 30
                flags.append(f"High volume: {total_requests} requests")
            elif total_requests >= 500:
                abuse_score += 20
                flags.append(f"Elevated volume: {total_requests} requests")
            
            # Factor 2: Rate limit errors (40 points)
            rate_limit_errors = group[group[status_col].str.contains(rate_limit_pattern, regex=True)].shape[0]
            if rate_limit_errors > 10:
                abuse_score += 40
                flags.append(f"Rate limit hits: {rate_limit_errors}")
            elif rate_limit_errors > 0:
                abuse_score += 20
                flags.append(f"Some rate limiting: {rate_limit_errors}")
            
            # Factor 3: API endpoint diversity (15 points for low diversity = scraping)
            unique_paths = group[url_col].nunique()
            path_diversity = unique_paths / total_requests if total_requests > 0 else 0
            if path_diversity < 0.1 and total_requests >= 100:
                abuse_score += 15
                flags.append(f"Low endpoint diversity: {unique_paths} unique paths")
            
            # Factor 4: Rapid-fire timing (15 points)
            if has_timestamp:
                time_span = (group[ts_col].max() - group[ts_col].min()).total_seconds() / 60
                if time_span > 0:
                    requests_per_minute = total_requests / time_span
                    if requests_per_minute >= self.HIGH_RATE_THRESHOLD:
                        abuse_score += 15
                        flags.append(f"High rate: {requests_per_minute:.1f} req/min")
            
            # Factor 5: Authentication failures (20 points)
            auth_failures = group[group[status_col].str.contains(auth_failure_pattern, regex=True)].shape[0]
            if auth_failures > total_requests * 0.3:
                abuse_score += 20
                flags.append(f"Auth failures: {auth_failures}")
            
            # Factor 6: Token switching (10 points if available)
            if has_token:
                token_col = col_map['auth_token']
                unique_tokens = group[token_col].nunique()
                if unique_tokens >= 5:
                    abuse_score += 10
                    flags.append(f"Token switching: {unique_tokens} different tokens")
            
            # Only include if score meets threshold
            if abuse_score >= self.MIN_ABUSE_SCORE:
                result_data = {
                    'source_ip': src_ip,
                    'total_requests': total_requests,
                    'unique_endpoints': unique_paths,
                    'rate_limit_errors': rate_limit_errors,
                    'auth_failures': auth_failures,
                    'endpoint_diversity': f"{path_diversity:.2%}",
                    'flags': ' | '.join(flags),
                    'abuse_score': min(abuse_score, 100)
                }
                
                if has_timestamp:
                    result_data['requests_per_minute'] = round(requests_per_minute, 1) if time_span > 0 else 0
                
                results.append(result_data)
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('abuse_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate API abuse visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['total_requests'],
            y=result_df['rate_limit_errors'],
            mode='markers',
            marker=dict(
                size=result_df['auth_failures'] / 10 + 10,
                color=result_df['abuse_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Abuse<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Requests: {result_df.iloc[i]['total_requests']}<br>Rate Limits: {result_df.iloc[i]['rate_limit_errors']}<br>Auth Fails: {result_df.iloc[i]['auth_failures']}<br>Score: {result_df.iloc[i]['abuse_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="API Abuse Detection: Request Volume vs Rate Limiting",
            xaxis_title="Total API Requests",
            yaxis_title="Rate Limit Errors",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for APIAbuseStrategy output columns."""
        return {
            'source_ip': 'The IP address making suspicious API requests',
            'total_requests': 'Total number of API requests made',
            'unique_endpoints': 'Number of different API endpoints accessed. Low diversity with high volume suggests scraping',
            'rate_limit_errors': 'Number of 429/509 rate limit errors received. High counts indicate aggressive automated access',
            'auth_failures': 'Number of 401/403 authentication failures. High rates suggest credential stuffing or token abuse',
            'endpoint_diversity': 'Percentage of unique endpoints vs total requests. Low values indicate repetitive scraping',
            'requests_per_minute': 'Average API request rate. Very high rates indicate bot activity',
            'flags': 'Specific API abuse indicators detected',
            'abuse_score': 'Overall API abuse suspiciousness score (0-100). Higher scores indicate likely automated scraping, credential stuffing, or API token abuse. Scores ≥50 suggest active API abuse that may impact service availability or indicate data theft attempt'
        }


class ShadowITStrategy(HuntStrategy):
    """
    Shadow IT Detector - Identifies unauthorized cloud services and unapproved SaaS usage.
    
    Detects employees using personal cloud storage, unapproved collaboration tools,
    unauthorized file sharing services, and data synchronization to non-corporate accounts.
    Critical for data loss prevention and compliance.
    """
    
    MIN_SHADOW_SCORE = 50
    # Common shadow IT services and personal cloud storage
    PERSONAL_CLOUD = [
        'dropbox.com', 'box.com', 'drive.google.com', 'docs.google.com', 
        'onedrive.live.com', 'icloud.com', 'mega.nz', 'mediafire.com',
        'wetransfer.com', 'sendspace.com', 'filemail.com', 'tresorit.com'
    ]
    COLLAB_TOOLS = [
        'slack.com', 'discord.com', 'telegram.org', 'whatsapp.com',
        'zoom.us', 'teams.live.com', 'skype.com', 'gotomeeting.com'
    ]
    FILE_SHARING = [
        'pastebin.com', 'github.com', 'gist.github.com', 'justpaste.it',
        'hastebin.com', 'dpaste.com', 'ghostbin.com'
    ]
    
    def _get_name(self) -> str:
        return "Shadow IT Detector (Unauthorized Cloud & SaaS)"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'dest_domain']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze web traffic to detect shadow IT usage.
        
        Args:
            df: DataFrame with web traffic logs
            col_map: Column mapping including source_ip, dest_domain
                     Optional: 'bytes_uploaded', 'user_agent'
        
        Returns:
            DataFrame with suspicious shadow IT usage
        """
        src_col = col_map['source_ip']
        domain_col = col_map['dest_domain']
        
        df = df.copy()
        df[domain_col] = df[domain_col].fillna('').astype(str).str.lower()
        
        # Check optional columns
        has_upload = 'bytes_uploaded' in col_map and col_map['bytes_uploaded'] in df.columns
        if has_upload:
            upload_col = col_map['bytes_uploaded']
            df[upload_col] = pd.to_numeric(df[upload_col], errors='coerce').fillna(0)
        
        results = []
        
        # Group by source IP
        for src_ip, group in df.groupby(src_col):
            total_connections = len(group)
            
            if total_connections < 5:
                continue
            
            shadow_score = 0.0
            flags = []
            cloud_services = set()
            collab_services = set()
            file_sharing_services = set()
            
            # Factor 1: Personal cloud storage usage (40 points)
            for service in self.PERSONAL_CLOUD:
                matching = group[group[domain_col].str.contains(service, regex=False, na=False)]
                if not matching.empty:
                    cloud_services.add(service)
                    shadow_score += min(len(matching) * 5, 40)
            
            if cloud_services:
                flags.append(f"Personal cloud: {', '.join(list(cloud_services)[:2])}")
            
            # Factor 2: Unauthorized collaboration tools (30 points)
            for service in self.COLLAB_TOOLS:
                matching = group[group[domain_col].str.contains(service, regex=False, na=False)]
                if not matching.empty:
                    collab_services.add(service)
                    shadow_score += min(len(matching) * 3, 30)
            
            if collab_services:
                flags.append(f"Collab tools: {', '.join(list(collab_services)[:2])}")
            
            # Factor 3: File sharing/paste sites (20 points)
            for service in self.FILE_SHARING:
                matching = group[group[domain_col].str.contains(service, regex=False, na=False)]
                if not matching.empty:
                    file_sharing_services.add(service)
                    shadow_score += min(len(matching) * 4, 20)
            
            if file_sharing_services:
                flags.append(f"File sharing: {', '.join(list(file_sharing_services)[:2])}")
            
            # Factor 4: Data upload volume (10 points)
            if has_upload:
                total_upload_mb = group[upload_col].sum() / (1024 * 1024)
                if total_upload_mb >= 100:
                    shadow_score += 10
                    flags.append(f"Upload volume: {total_upload_mb:.1f} MB")
            
            # Factor 5: Multiple shadow IT services (10 points)
            total_shadow_services = len(cloud_services) + len(collab_services) + len(file_sharing_services)
            if total_shadow_services >= 3:
                shadow_score += 10
                flags.append(f"Multiple services: {total_shadow_services}")
            
            # Only include if score meets threshold
            if shadow_score >= self.MIN_SHADOW_SCORE:
                result_data = {
                    'source_ip': src_ip,
                    'total_connections': total_connections,
                    'cloud_services': ', '.join(list(cloud_services)[:3]) if cloud_services else 'None',
                    'collab_tools': ', '.join(list(collab_services)[:3]) if collab_services else 'None',
                    'file_sharing': ', '.join(list(file_sharing_services)[:3]) if file_sharing_services else 'None',
                    'total_shadow_services': total_shadow_services,
                    'flags': ' | '.join(flags),
                    'shadow_score': min(shadow_score, 100)
                }
                
                if has_upload:
                    result_data['upload_mb'] = round(total_upload_mb, 1)
                
                results.append(result_data)
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('shadow_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate shadow IT visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=result_df['total_connections'],
            y=result_df['total_shadow_services'],
            mode='markers',
            marker=dict(
                size=15,
                color=result_df['shadow_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Shadow IT<br>Score")
            ),
            text=[f"Source: {result_df.iloc[i]['source_ip']}<br>Connections: {result_df.iloc[i]['total_connections']}<br>Services: {result_df.iloc[i]['total_shadow_services']}<br>Score: {result_df.iloc[i]['shadow_score']:.0f}" 
                  for i in range(len(result_df))],
            hovertemplate='%{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Shadow IT Detection: Connection Volume vs Service Diversity",
            xaxis_title="Total Connections",
            yaxis_title="Number of Different Shadow IT Services",
            hovermode='closest',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for ShadowITStrategy output columns."""
        return {
            'source_ip': 'The IP address accessing unauthorized services',
            'total_connections': 'Total number of connections to shadow IT services',
            'cloud_services': 'Personal cloud storage services detected (Dropbox, Google Drive, OneDrive, etc.)',
            'collab_tools': 'Unauthorized collaboration tools detected (Slack, Discord, Telegram, etc.)',
            'file_sharing': 'File sharing and paste sites detected (Pastebin, GitHub Gist, etc.)',
            'total_shadow_services': 'Total count of different shadow IT services used',
            'upload_mb': 'Total data uploaded to shadow IT services in megabytes',
            'flags': 'Specific shadow IT usage indicators detected',
            'shadow_score': 'Overall shadow IT risk score (0-100). Higher scores indicate significant use of unauthorized cloud services and collaboration tools. Scores ≥50 suggest active data exfiltration risk or policy violations requiring immediate attention'
        }


class PrivilegeEscalationStrategy(HuntStrategy):
    """
    Detects suspicious privilege escalation attempts.
    
    Identifies patterns indicating unauthorized attempts to gain elevated privileges
    including sudo abuse, runas commands, token manipulation, and suspicious
    administrative tool usage.
    """
    
    # Suspicious commands/processes indicating privilege escalation
    PRIV_ESC_KEYWORDS = [
        'sudo', 'su -', 'runas', 'psexec', 'whoami /priv', 'net localgroup',
        'net user', 'icacls', 'takeown', 'gpasswd', 'usermod', 'passwd',
        'mimikatz', 'gsecdump', 'lsadump', 'sekurlsa', 'elevate',
        'bypassuac', 'invoke-privilege', 'invoke-mimikatz', 'getsystem',
        'get-credential', 'enable-privilege', 'seimpersonate', 'setoolkit'
    ]
    
    # Administrative tools that should be monitored
    ADMIN_TOOLS = [
        'net.exe', 'wmic.exe', 'sc.exe', 'schtasks.exe', 'reg.exe',
        'powershell.exe', 'cmd.exe', 'psexec.exe', 'at.exe', 'cscript.exe'
    ]
    
    def _get_name(self) -> str:
        return "Privilege Escalation Detector"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'username', 'command', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze for privilege escalation patterns.
        
        Detection logic:
        1. Commands containing privilege escalation keywords
        2. Repeated administrative tool usage
        3. Token manipulation patterns
        4. Suspicious service/scheduled task creation
        5. Multiple privilege escalation techniques from same source
        """
        src_col = col_map['source_ip']
        user_col = col_map['username']
        cmd_col = col_map['command']
        proc_col = col_map['process_name']
        
        results = []
        
        # Group by source IP and username
        grouped = df.groupby([src_col, user_col])
        
        for (src_ip, username), group in grouped:
            priv_esc_score = 0
            flags = []
            escalation_methods = set()
            admin_tool_count = 0
            suspicious_commands = []
            
            for _, row in group.iterrows():
                command = str(row[cmd_col]).lower() if pd.notna(row[cmd_col]) else ""
                process = str(row[proc_col]).lower() if pd.notna(row[proc_col]) else ""
                
                # Check for privilege escalation keywords
                for keyword in self.PRIV_ESC_KEYWORDS:
                    if keyword.lower() in command or keyword.lower() in process:
                        priv_esc_score += 10
                        escalation_methods.add(keyword)
                        if len(suspicious_commands) < 5:
                            suspicious_commands.append(keyword)
                
                # Check for administrative tool usage
                for tool in self.ADMIN_TOOLS:
                    if tool.lower() in process:
                        admin_tool_count += 1
                        priv_esc_score += 5
            
            # Scoring logic
            if len(escalation_methods) > 3:
                priv_esc_score += 30
                flags.append("multiple_escalation_techniques")
            
            if admin_tool_count > 10:
                priv_esc_score += 25
                flags.append("excessive_admin_tools")
            
            if 'sudo' in escalation_methods or 'runas' in escalation_methods:
                priv_esc_score += 15
                flags.append("direct_elevation_attempt")
            
            if 'mimikatz' in escalation_methods or 'sekurlsa' in escalation_methods:
                priv_esc_score += 40
                flags.append("credential_dumping_tool")
            
            # Cap score at 100
            priv_esc_score = min(priv_esc_score, 100)
            
            if priv_esc_score >= 50:
                results.append({
                    'source_ip': src_ip,
                    'username': username,
                    'total_commands': len(group),
                    'escalation_methods': ', '.join(sorted(escalation_methods)[:10]),
                    'admin_tool_count': admin_tool_count,
                    'method_diversity': len(escalation_methods),
                    'flags': ', '.join(flags),
                    'priv_esc_score': priv_esc_score
                })
        
        result_df = pd.DataFrame(results)
        
        if not result_df.empty:
            result_df = result_df.sort_values('priv_esc_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate visualizations for privilege escalation analysis."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        # Top 15 sources by escalation score
        top_sources = result_df.nlargest(15, 'priv_esc_score')
        
        fig.add_trace(go.Bar(
            x=top_sources['priv_esc_score'],
            y=top_sources['source_ip'] + ' (' + top_sources['username'] + ')',
            orientation='h',
            marker=dict(
                color=top_sources['priv_esc_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Escalation Score")
            ),
            text=top_sources['method_diversity'],
            textposition='auto',
            hovertemplate='<b>%{y}</b><br>Score: %{x}<br>Methods: %{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Top Privilege Escalation Attempts by Source',
            xaxis_title='Privilege Escalation Score',
            yaxis_title='Source IP (Username)',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for PrivilegeEscalationStrategy output columns."""
        return {
            'source_ip': 'The IP address from which privilege escalation attempts originated',
            'username': 'The user account attempting privilege escalation',
            'total_commands': 'Total number of commands executed by this user from this IP',
            'escalation_methods': 'Specific privilege escalation techniques detected (sudo, mimikatz, etc.)',
            'admin_tool_count': 'Number of administrative tool invocations detected',
            'method_diversity': 'Count of different escalation techniques used',
            'flags': 'Specific indicators detected (multiple_escalation_techniques, credential_dumping_tool, etc.)',
            'priv_esc_score': 'Overall privilege escalation risk score (0-100). Higher scores indicate aggressive attempts to gain elevated privileges. Scores ≥75 suggest active privilege escalation attacks. Scores ≥50 warrant immediate investigation'
        }


class WebshellDetectionStrategy(HuntStrategy):
    """
    Identifies web shell backdoor patterns in web server traffic.
    
    Detects suspicious file uploads, command execution via web requests,
    POST requests to unusual files, and other web shell indicators.
    """
    
    # Common web shell file names and patterns
    WEBSHELL_FILES = [
        'c99.php', 'r57.php', 'shell.php', 'cmd.php', 'backdoor.php',
        'webshell.asp', 'shell.asp', 'cmd.asp', 'upload.php',
        'wso.php', 'b374k.php', 'alfa.php', 'eval.php', 'exec.php',
        'system.jsp', 'cmd.jsp', 'shell.jsp', 'jspshell.jsp'
    ]
    
    # Suspicious parameters in web requests
    SUSPICIOUS_PARAMS = [
        'cmd', 'exec', 'command', 'execute', 'shell', 'run', 'ping',
        'system', 'proc_open', 'passthru', 'eval', 'base64_decode',
        'backdoor', 'upload', 'download', 'file'
    ]
    
    # Suspicious user agents often used by web shells
    WEBSHELL_AGENTS = [
        'python-requests', 'curl', 'wget', 'nikto', 'sqlmap',
        'havij', 'acunetix', 'nessus', 'burpsuite', 'metasploit'
    ]
    
    def _get_name(self) -> str:
        return "Webshell Detection"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'uri', 'method', 'status_code', 'user_agent']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze for web shell patterns.
        
        Detection logic:
        1. Suspicious file names in URIs
        2. POST requests to script files
        3. Command execution parameters
        4. Tool/bot user agents accessing unusual files
        5. Long query strings with encoded content
        6. Successful requests (200) to suspicious endpoints
        """
        src_col = col_map['source_ip']
        uri_col = col_map['uri']
        method_col = col_map['method']
        status_col = col_map['status_code']
        ua_col = col_map['user_agent']
        
        results = []
        
        # Group by source IP
        grouped = df.groupby(src_col)
        
        for src_ip, group in grouped:
            webshell_score = 0
            flags = []
            suspicious_uris = set()
            post_to_scripts = 0
            suspicious_params_found = set()
            tool_agents = 0
            
            for _, row in group.iterrows():
                uri = str(row[uri_col]).lower() if pd.notna(row[uri_col]) else ""
                method = str(row[method_col]).upper() if pd.notna(row[method_col]) else ""
                status = str(row[status_col]) if pd.notna(row[status_col]) else ""
                user_agent = str(row[ua_col]).lower() if pd.notna(row[ua_col]) else ""
                
                # Check for web shell file names
                for shell_file in self.WEBSHELL_FILES:
                    if shell_file in uri:
                        webshell_score += 30
                        suspicious_uris.add(shell_file)
                        flags.append("webshell_filename")
                        break
                
                # Check for POST to script files with success status
                if method == 'POST' and any(ext in uri for ext in ['.php', '.asp', '.jsp', '.cgi']):
                    post_to_scripts += 1
                    if '200' in status:
                        webshell_score += 15
                
                # Check for suspicious parameters
                for param in self.SUSPICIOUS_PARAMS:
                    if param in uri:
                        suspicious_params_found.add(param)
                        webshell_score += 8
                
                # Check for tool/bot user agents
                for agent in self.WEBSHELL_AGENTS:
                    if agent in user_agent:
                        tool_agents += 1
                        webshell_score += 10
                        break
                
                # Long query strings may contain encoded commands
                if len(uri) > 200 and ('base64' in uri or 'eval' in uri):
                    webshell_score += 20
                    flags.append("encoded_command")
            
            # Additional scoring
            if post_to_scripts > 5:
                webshell_score += 25
                flags.append("excessive_post_to_scripts")
            
            if len(suspicious_params_found) > 3:
                webshell_score += 20
                flags.append("multiple_suspicious_params")
            
            if tool_agents > 0 and len(suspicious_uris) > 0:
                webshell_score += 30
                flags.append("tool_accessing_suspicious_file")
            
            # Cap score at 100
            webshell_score = min(webshell_score, 100)
            
            if webshell_score >= 50:
                results.append({
                    'source_ip': src_ip,
                    'total_requests': len(group),
                    'suspicious_uris': ', '.join(sorted(suspicious_uris)[:5]) if suspicious_uris else 'N/A',
                    'post_to_scripts': post_to_scripts,
                    'suspicious_params': ', '.join(sorted(suspicious_params_found)[:5]),
                    'tool_agent_requests': tool_agents,
                    'flags': ', '.join(set(flags)),
                    'webshell_score': webshell_score
                })
        
        result_df = pd.DataFrame(results)
        
        if not result_df.empty:
            result_df = result_df.sort_values('webshell_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate visualizations for web shell detection."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        # Top 15 sources by webshell score
        top_sources = result_df.nlargest(15, 'webshell_score')
        
        fig.add_trace(go.Bar(
            x=top_sources['webshell_score'],
            y=top_sources['source_ip'],
            orientation='h',
            marker=dict(
                color=top_sources['webshell_score'],
                colorscale='Oranges',
                showscale=True,
                colorbar=dict(title="Webshell Score")
            ),
            text=top_sources['post_to_scripts'],
            textposition='auto',
            hovertemplate='<b>%{y}</b><br>Score: %{x}<br>POST to scripts: %{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Top Web Shell Indicators by Source IP',
            xaxis_title='Web Shell Detection Score',
            yaxis_title='Source IP',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for WebshellDetectionStrategy output columns."""
        return {
            'source_ip': 'The IP address exhibiting web shell behavior',
            'total_requests': 'Total number of web requests from this IP',
            'suspicious_uris': 'Known web shell file names detected in URIs (c99.php, r57.php, etc.)',
            'post_to_scripts': 'Count of POST requests to script files (.php, .asp, .jsp)',
            'suspicious_params': 'Command execution parameters found (cmd, exec, shell, eval, etc.)',
            'tool_agent_requests': 'Requests from attack tools or scanners',
            'flags': 'Specific web shell indicators (webshell_filename, encoded_command, etc.)',
            'webshell_score': 'Overall web shell risk score (0-100). Higher scores indicate probable web shell access or deployment. Scores ≥75 suggest active web shell usage. Scores ≥50 require immediate investigation'
        }


class CredentialDumpingStrategy(HuntStrategy):
    """
    Detects memory scraping and credential theft tool usage.
    
    Identifies patterns indicating credential dumping from memory, registry,
    or disk including LSASS access, SAM database queries, and credential harvesting tools.
    """
    
    # Known credential dumping tools
    CRED_DUMP_TOOLS = [
        'mimikatz', 'procdump', 'dumpert', 'nanodump', 'pypykatz',
        'gsecdump', 'wce.exe', 'pwdump', 'fgdump', 'hashdump',
        'lazagne', 'secretsdump', 'lsassy', 'sharpkatz', 'safetykatz',
        'rubeus', 'kekeo', 'impacket'
    ]
    
    # Suspicious process access patterns
    SUSPICIOUS_PROCESSES = [
        'lsass.exe', 'lsass', 'sam', 'security', 'system', 'ntds.dit',
        'credential', 'chrome.exe', 'firefox.exe', 'browser'
    ]
    
    # Suspicious commands indicating credential access
    CRED_ACCESS_KEYWORDS = [
        'sekurlsa', 'logonpasswords', 'minidump', 'lsadump', 'sam',
        'reg save hklm\\sam', 'reg save hklm\\system', 'reg save hklm\\security',
        'vaultcmd', 'cmdkey', 'netsh wlan', 'dpapi', 'extract',
        'export credential', 'get-credential'
    ]
    
    def _get_name(self) -> str:
        return "Credential Dumping Detector"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'username', 'process_name', 'command']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze for credential dumping patterns.
        
        Detection logic:
        1. Known credential dumping tools
        2. LSASS process access
        3. Registry hive exports (SAM, SECURITY, SYSTEM)
        4. Browser credential theft
        5. Multiple credential access techniques
        """
        src_col = col_map['source_ip']
        user_col = col_map['username']
        proc_col = col_map['process_name']
        cmd_col = col_map['command']
        
        results = []
        
        # Group by source IP and username
        grouped = df.groupby([src_col, user_col])
        
        for (src_ip, username), group in grouped:
            cred_dump_score = 0
            flags = []
            tools_detected = set()
            process_access = set()
            commands_used = []
            
            for _, row in group.iterrows():
                process = str(row[proc_col]).lower() if pd.notna(row[proc_col]) else ""
                command = str(row[cmd_col]).lower() if pd.notna(row[cmd_col]) else ""
                
                # Check for credential dumping tools
                for tool in self.CRED_DUMP_TOOLS:
                    if tool.lower() in process or tool.lower() in command:
                        cred_dump_score += 35
                        tools_detected.add(tool)
                        flags.append("cred_dump_tool")
                
                # Check for suspicious process access
                for proc_target in self.SUSPICIOUS_PROCESSES:
                    if proc_target.lower() in process or proc_target.lower() in command:
                        process_access.add(proc_target)
                        if 'lsass' in proc_target.lower():
                            cred_dump_score += 30
                            flags.append("lsass_access")
                        else:
                            cred_dump_score += 15
                
                # Check for credential access keywords
                for keyword in self.CRED_ACCESS_KEYWORDS:
                    if keyword.lower() in command:
                        cred_dump_score += 20
                        if len(commands_used) < 5:
                            commands_used.append(keyword)
                        
                        if 'reg save' in keyword:
                            flags.append("registry_hive_export")
            
            # Additional scoring
            if len(tools_detected) > 0:
                cred_dump_score += 25
            
            if len(process_access) > 2:
                cred_dump_score += 20
                flags.append("multiple_target_processes")
            
            if len(commands_used) > 3:
                cred_dump_score += 15
                flags.append("multiple_access_methods")
            
            # Cap score at 100
            cred_dump_score = min(cred_dump_score, 100)
            
            if cred_dump_score >= 50:
                results.append({
                    'source_ip': src_ip,
                    'username': username,
                    'total_events': len(group),
                    'tools_detected': ', '.join(sorted(tools_detected)[:5]) if tools_detected else 'N/A',
                    'process_targets': ', '.join(sorted(process_access)[:5]),
                    'access_methods': len(commands_used),
                    'flags': ', '.join(set(flags)),
                    'cred_dump_score': cred_dump_score
                })
        
        result_df = pd.DataFrame(results)
        
        if not result_df.empty:
            result_df = result_df.sort_values('cred_dump_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate visualizations for credential dumping analysis."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        # Top 15 sources by credential dumping score
        top_sources = result_df.nlargest(15, 'cred_dump_score')
        
        fig.add_trace(go.Bar(
            x=top_sources['cred_dump_score'],
            y=top_sources['source_ip'] + ' (' + top_sources['username'] + ')',
            orientation='h',
            marker=dict(
                color=top_sources['cred_dump_score'],
                colorscale='Purples',
                showscale=True,
                colorbar=dict(title="Credential Dump Score")
            ),
            text=top_sources['access_methods'],
            textposition='auto',
            hovertemplate='<b>%{y}</b><br>Score: %{x}<br>Methods: %{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Top Credential Dumping Activity by Source',
            xaxis_title='Credential Dumping Score',
            yaxis_title='Source IP (Username)',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for CredentialDumpingStrategy output columns."""
        return {
            'source_ip': 'The IP address from which credential dumping activity originated',
            'username': 'The user account performing credential dumping operations',
            'total_events': 'Total number of suspicious events detected',
            'tools_detected': 'Known credential harvesting tools identified (mimikatz, procdump, etc.)',
            'process_targets': 'Processes accessed for credential theft (lsass, browser, etc.)',
            'access_methods': 'Number of different credential access techniques used',
            'flags': 'Specific indicators (lsass_access, registry_hive_export, cred_dump_tool, etc.)',
            'cred_dump_score': 'Overall credential dumping risk score (0-100). Higher scores indicate active credential theft. Scores ≥75 suggest sophisticated credential harvesting. Scores ≥50 require immediate investigation and credential rotation'
        }


class RansomwareIndicatorStrategy(HuntStrategy):
    """
    Detects early warning signs of ransomware deployment.
    
    Identifies pre-ransomware indicators including shadow copy deletion,
    backup interference, mass file encryption patterns, and ransomware
    preparation activities.
    """
    
    # Commands used in ransomware attacks
    RANSOMWARE_COMMANDS = [
        'vssadmin delete shadows', 'wmic shadowcopy delete', 'bcdedit',
        'wbadmin delete catalog', 'del /s /f /q', 'cipher /w',
        'net stop backup', 'net stop vss', 'sc stop backup',
        'delete backup', 'disable recovery', 'bootstatuspolicy ignoreallfailures'
    ]
    
    # File extensions commonly used by ransomware
    RANSOMWARE_EXTENSIONS = [
        '.locked', '.encrypted', '.crypto', '.cerber', '.locky',
        '.zepto', '.odin', '.shit', '.vvv', '.ccc', '.abc',
        '.xyz', '.zzz', '.micro', '.dharma', '.wallet', '.wcry'
    ]
    
    # Processes often used in ransomware deployment
    RANSOMWARE_PROCESSES = [
        'powershell', 'cmd', 'wscript', 'cscript', 'psexec',
        'wmic', 'vssadmin', 'bcdedit', 'wbadmin', 'cipher'
    ]
    
    def _get_name(self) -> str:
        return "Ransomware Indicator Detector"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'username', 'command', 'file_path']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze for ransomware indicators.
        
        Detection logic:
        1. Shadow copy deletion commands
        2. Backup service interference
        3. Boot configuration tampering
        4. Mass file operations
        5. Ransomware-related file extensions
        6. Multiple preparation steps in sequence
        """
        src_col = col_map['source_ip']
        user_col = col_map['username']
        cmd_col = col_map['command']
        file_col = col_map['file_path']
        
        results = []
        
        # Group by source IP and username
        grouped = df.groupby([src_col, user_col])
        
        for (src_ip, username), group in grouped:
            ransomware_score = 0
            flags = []
            commands_matched = set()
            file_operations = 0
            encrypted_files = 0
            prep_steps = 0
            
            for _, row in group.iterrows():
                command = str(row[cmd_col]).lower() if pd.notna(row[cmd_col]) else ""
                file_path = str(row[file_col]).lower() if pd.notna(row[file_col]) else ""
                
                # Check for ransomware commands
                for ransom_cmd in self.RANSOMWARE_COMMANDS:
                    if ransom_cmd.lower() in command:
                        commands_matched.add(ransom_cmd)
                        
                        if 'shadow' in ransom_cmd or 'vss' in ransom_cmd:
                            ransomware_score += 40
                            flags.append("shadow_copy_deletion")
                            prep_steps += 1
                        elif 'backup' in ransom_cmd:
                            ransomware_score += 35
                            flags.append("backup_interference")
                            prep_steps += 1
                        elif 'bcdedit' in ransom_cmd or 'bootstatuspolicy' in ransom_cmd:
                            ransomware_score += 30
                            flags.append("boot_config_tampering")
                            prep_steps += 1
                        else:
                            ransomware_score += 15
                
                # Check for ransomware file extensions
                for ext in self.RANSOMWARE_EXTENSIONS:
                    if ext in file_path:
                        encrypted_files += 1
                        ransomware_score += 10
                
                # Count file operations
                if any(op in command for op in ['del ', 'rm ', 'cipher', 'copy', 'move']):
                    file_operations += 1
            
            # Additional scoring
            if encrypted_files > 10:
                ransomware_score += 40
                flags.append("mass_file_encryption")
            
            if file_operations > 50:
                ransomware_score += 25
                flags.append("mass_file_operations")
            
            if prep_steps >= 2:
                ransomware_score += 30
                flags.append("multiple_prep_steps")
            
            if len(commands_matched) > 3:
                ransomware_score += 25
                flags.append("comprehensive_attack_prep")
            
            # Cap score at 100
            ransomware_score = min(ransomware_score, 100)
            
            if ransomware_score >= 50:
                results.append({
                    'source_ip': src_ip,
                    'username': username,
                    'total_events': len(group),
                    'preparation_commands': ', '.join(sorted(commands_matched)[:5]),
                    'encrypted_files': encrypted_files,
                    'file_operations': file_operations,
                    'preparation_steps': prep_steps,
                    'flags': ', '.join(set(flags)),
                    'ransomware_score': ransomware_score
                })
        
        result_df = pd.DataFrame(results)
        
        if not result_df.empty:
            result_df = result_df.sort_values('ransomware_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate visualizations for ransomware indicator analysis."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        fig = go.Figure()
        
        # Top 15 sources by ransomware score
        top_sources = result_df.nlargest(15, 'ransomware_score')
        
        fig.add_trace(go.Bar(
            x=top_sources['ransomware_score'],
            y=top_sources['source_ip'] + ' (' + top_sources['username'] + ')',
            orientation='h',
            marker=dict(
                color=top_sources['ransomware_score'],
                colorscale='YlOrRd',
                showscale=True,
                colorbar=dict(title="Ransomware Score")
            ),
            text=top_sources['preparation_steps'],
            textposition='auto',
            hovertemplate='<b>%{y}</b><br>Score: %{x}<br>Prep Steps: %{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Top Ransomware Indicators by Source',
            xaxis_title='Ransomware Indicator Score',
            yaxis_title='Source IP (Username)',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for RansomwareIndicatorStrategy output columns."""
        return {
            'source_ip': 'The IP address from which ransomware preparation activity originated',
            'username': 'The user account performing ransomware-related actions',
            'total_events': 'Total number of suspicious events detected',
            'preparation_commands': 'Pre-encryption commands detected (shadow deletion, backup interference, etc.)',
            'encrypted_files': 'Count of files with ransomware-related extensions',
            'file_operations': 'Total file manipulation operations (delete, move, cipher, etc.)',
            'preparation_steps': 'Number of distinct ransomware preparation activities',
            'flags': 'Specific indicators (shadow_copy_deletion, backup_interference, mass_file_encryption, etc.)',
            'ransomware_score': 'Overall ransomware deployment risk score (0-100). Higher scores indicate imminent or active ransomware attack. Scores ≥75 require immediate incident response and system isolation. Scores ≥50 indicate active preparation and demand urgent attention'
        }


class SupplyChainAttackStrategy(HuntStrategy):
    """
    Detect supply chain attacks via compromised packages and dependencies.
    
    Identifies suspicious package installations, unusual registry access,
    typosquatting attempts, and malicious dependency downloads. Critical
    for detecting attacks like SolarWinds, Log4Shell, and npm package compromises.
    """
    
    SUSPICIOUS_PACKAGE_PATTERNS = [
        r'.*-dev-.*', r'.*\.test\..*', r'.*-debug-.*',  # Development packages in production
        r'.*admin.*password.*', r'.*secret.*key.*',  # Suspicious names
        r'.*backdoor.*', r'.*malware.*', r'.*trojan.*',  # Obvious malware
        r'.*\d{8,}.*',  # Suspiciously random numbers
    ]
    
    SUSPICIOUS_REGISTRIES = [
        'pastebin.com', 'raw.githubusercontent.com', 'bit.ly',
        'tinyurl.com', 'temp-host.com', 'suspicious-registry.xyz'
    ]
    
    TYPOSQUAT_TARGETS = [
        'numpy', 'pandas', 'requests', 'flask', 'django',
        'express', 'react', 'lodash', 'moment', 'axios'
    ]
    
    def _get_name(self) -> str:
        return "Supply Chain Attack Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'package_name', 'registry_url', 'user_agent']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """Analyze package installations for supply chain threats."""
        
        # Map columns
        ts_col = col_map['timestamp']
        src_col = col_map['source_ip']
        pkg_col = col_map['package_name']
        reg_col = col_map['registry_url']
        ua_col = col_map['user_agent']
        
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df[ts_col]):
            df[ts_col] = pd.to_datetime(df[ts_col], errors='coerce')
        
        results = []
        
        # Group by source IP and package
        for (src_ip, pkg_name), group in df.groupby([src_col, pkg_col]):
            if pd.isna(pkg_name) or pkg_name == '':
                continue
            
            score = 0
            flags = []
            
            # Check for suspicious package patterns
            pkg_lower = str(pkg_name).lower()
            for pattern in self.SUSPICIOUS_PACKAGE_PATTERNS:
                if re.match(pattern, pkg_lower, re.IGNORECASE):
                    score += 20
                    flags.append('suspicious_naming')
                    break
            
            # Check for suspicious registries
            registry = str(group[reg_col].iloc[0]) if len(group) > 0 else ''
            for suspicious_reg in self.SUSPICIOUS_REGISTRIES:
                if suspicious_reg in registry.lower():
                    score += 30
                    flags.append('untrusted_registry')
                    break
            
            # Check for typosquatting
            for target in self.TYPOSQUAT_TARGETS:
                if self._is_typosquat(pkg_lower, target):
                    score += 40
                    flags.append('typosquatting')
                    break
            
            # Check for automated/script-based downloads (potential mass compromise)
            user_agents = group[ua_col].unique()
            automated_ua = sum(1 for ua in user_agents if any(x in str(ua).lower() for x in ['python', 'curl', 'wget', 'bot', 'script']))
            if automated_ua > 0:
                score += 15
                flags.append('automated_download')
            
            # Check for unusual installation volume
            install_count = len(group)
            if install_count > 10:
                score += 10
                flags.append('high_volume')
            
            # Check for rapid sequential installations
            if len(group) > 1:
                time_diffs = group.sort_values(ts_col)[ts_col].diff().dt.total_seconds().dropna()
                if len(time_diffs) > 0 and time_diffs.median() < 5:
                    score += 15
                    flags.append('rapid_installation')
            
            if score >= 40:  # Only report suspicious packages
                results.append({
                    'source_ip': src_ip,
                    'package_name': pkg_name,
                    'registry_url': registry,
                    'install_count': install_count,
                    'first_seen': group[ts_col].min(),
                    'last_seen': group[ts_col].max(),
                    'automated_downloads': automated_ua,
                    'flags': ', '.join(set(flags)),
                    'supply_chain_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('supply_chain_score', ascending=False)
        
        return result_df
    
    def _is_typosquat(self, pkg_name: str, target: str) -> bool:
        """
        Check if package name is likely typosquatting target.
        
        Uses simplified Levenshtein distance (edit distance of 1).
        Note: O(n) complexity where n is package name length (typically < 50 chars).
        For production use with thousands of targets, consider using python-Levenshtein library.
        """
        if pkg_name == target:
            return False
        
        # Levenshtein distance approximation (edit distance = 1)
        if len(pkg_name) != len(target):
            if abs(len(pkg_name) - len(target)) == 1:
                # Check for single character insertion/deletion
                shorter = pkg_name if len(pkg_name) < len(target) else target
                longer = target if len(pkg_name) < len(target) else pkg_name
                for i in range(len(longer)):
                    if longer[:i] + longer[i+1:] == shorter:
                        return True
        else:
            # Check for single character substitution
            diff_count = sum(1 for a, b in zip(pkg_name, target) if a != b)
            if diff_count == 1:
                return True
        
        return False
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate supply chain threat visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Top packages by score
        top_packages = result_df.nlargest(15, 'supply_chain_score')
        
        fig = go.Figure(go.Bar(
            x=top_packages['supply_chain_score'],
            y=top_packages['package_name'],
            orientation='h',
            marker=dict(
                color=top_packages['supply_chain_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Threat Score")
            ),
            text=top_packages['install_count'],
            textposition='auto',
            hovertemplate='<b>%{y}</b><br>Score: %{x}<br>Installs: %{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Supply Chain Threat: Suspicious Packages',
            xaxis_title='Supply Chain Attack Score',
            yaxis_title='Package Name',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for SupplyChainAttackStrategy output columns."""
        return {
            'source_ip': 'The IP address downloading suspicious packages',
            'package_name': 'Name of the potentially malicious package',
            'registry_url': 'Source registry or repository URL',
            'install_count': 'Number of times this package was installed',
            'first_seen': 'First installation timestamp',
            'last_seen': 'Most recent installation timestamp',
            'automated_downloads': 'Count of automated/scripted download attempts',
            'flags': 'Specific threat indicators (typosquatting, untrusted_registry, suspicious_naming, etc.)',
            'supply_chain_score': 'Supply chain attack risk score (0-100). Scores ≥75 indicate likely malicious packages. Scores ≥50 require immediate investigation and package quarantine'
        }


class ContainerEscapeStrategy(HuntStrategy):
    """
    Detect container escape attempts and breakout techniques.
    
    Identifies suspicious container activity including privilege escalation,
    host filesystem access, kernel module loading, and Docker socket abuse.
    Essential for securing containerized environments.
    """
    
    ESCAPE_COMMANDS = [
        'nsenter', 'unshare', 'capsh', 'setcap', 'mount',
        'insmod', 'modprobe', 'docker', 'crictl', 'runc'
    ]
    
    DANGEROUS_PATHS = [
        '/proc/sys/kernel', '/sys/kernel', '/dev/mem', '/dev/kmem',
        '/var/run/docker.sock', '/run/containerd', '/host', '/rootfs'
    ]
    
    BREAKOUT_CAPABILITIES = [
        'CAP_SYS_ADMIN', 'CAP_SYS_MODULE', 'CAP_SYS_RAWIO',
        'CAP_SYS_PTRACE', 'CAP_DAC_OVERRIDE', 'CAP_SYS_BOOT'
    ]
    
    def _get_name(self) -> str:
        return "Container Escape Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'container_id', 'command', 'user', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """Analyze container activity for escape attempts."""
        
        # Map columns
        ts_col = col_map['timestamp']
        cont_col = col_map['container_id']
        cmd_col = col_map['command']
        user_col = col_map['user']
        proc_col = col_map['process_name']
        
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df[ts_col]):
            df[ts_col] = pd.to_datetime(df[ts_col], errors='coerce')
        
        results = []
        
        # Group by container
        for container_id, group in df.groupby(cont_col):
            if pd.isna(container_id) or container_id == '':
                continue
            
            score = 0
            flags = []
            escape_attempts = 0
            dangerous_commands = []
            
            for _, row in group.iterrows():
                cmd = str(row[cmd_col]).lower() if pd.notna(row[cmd_col]) else ''
                proc = str(row[proc_col]).lower() if pd.notna(row[proc_col]) else ''
                user = str(row[user_col]).lower() if pd.notna(row[user_col]) else ''
                
                # Check for escape commands
                for escape_cmd in self.ESCAPE_COMMANDS:
                    if escape_cmd in cmd or escape_cmd in proc:
                        score += 15
                        escape_attempts += 1
                        dangerous_commands.append(escape_cmd)
                        flags.append('escape_command')
                        break
                
                # Check for dangerous path access
                for danger_path in self.DANGEROUS_PATHS:
                    if danger_path in cmd:
                        score += 20
                        flags.append('host_filesystem_access')
                        break
                
                # Check for capability abuse
                for cap in self.BREAKOUT_CAPABILITIES:
                    if cap in cmd:
                        score += 25
                        flags.append('dangerous_capability')
                        break
                
                # Check for root/privileged user
                if user in ['root', '0'] or 'privileged' in cmd:
                    score += 10
                    flags.append('privileged_execution')
                
                # Check for namespace manipulation
                if any(x in cmd for x in ['namespace', 'cgroup', '/proc/self']):
                    score += 20
                    flags.append('namespace_manipulation')
            
            # Check for rapid privilege escalation attempts
            if escape_attempts > 5:
                score += 20
                flags.append('multiple_escape_attempts')
            
            if score >= 50:  # Only report significant escape attempts
                results.append({
                    'container_id': container_id,
                    'user': group[user_col].iloc[0] if len(group) > 0 else '',
                    'total_commands': len(group),
                    'escape_attempts': escape_attempts,
                    'dangerous_commands': ', '.join(list(set(dangerous_commands))[:5]),
                    'first_seen': group[ts_col].min(),
                    'last_seen': group[ts_col].max(),
                    'flags': ', '.join(set(flags)),
                    'escape_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('escape_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate container escape visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Top containers by score
        top_containers = result_df.nlargest(15, 'escape_score')
        
        fig = go.Figure(go.Bar(
            x=top_containers['escape_score'],
            y=top_containers['container_id'],
            orientation='h',
            marker=dict(
                color=top_containers['escape_score'],
                colorscale='OrRd',
                showscale=True,
                colorbar=dict(title="Escape Score")
            ),
            text=top_containers['escape_attempts'],
            textposition='auto',
            hovertemplate='<b>%{y}</b><br>Score: %{x}<br>Attempts: %{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Container Escape Attempts',
            xaxis_title='Container Escape Risk Score',
            yaxis_title='Container ID',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for ContainerEscapeStrategy output columns."""
        return {
            'container_id': 'Unique identifier of the container attempting escape',
            'user': 'User account executing commands in the container',
            'total_commands': 'Total number of commands executed',
            'escape_attempts': 'Count of identified escape attempt commands',
            'dangerous_commands': 'List of specific escape-related commands detected',
            'first_seen': 'First suspicious activity timestamp',
            'last_seen': 'Most recent suspicious activity timestamp',
            'flags': 'Specific escape indicators (escape_command, host_filesystem_access, dangerous_capability, etc.)',
            'escape_score': 'Container escape risk score (0-100). Scores ≥75 indicate active breakout attempts requiring immediate containment. Scores ≥50 suggest reconnaissance for escape vectors'
        }


class DNSExfiltrationStrategy(HuntStrategy):
    """
    Detect DNS-based data exfiltration beyond standard tunneling detection.
    
    Identifies covert data exfiltration through DNS queries using techniques
    like subdomain encoding, TXT record abuse, and high-volume query patterns.
    Complements the existing DNS Anomaly strategy with exfiltration focus.
    """
    
    def _get_name(self) -> str:
        return "DNS Exfiltration Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'query_name', 'query_type', 'response_size']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """Analyze DNS queries for data exfiltration patterns."""
        
        # Map columns
        ts_col = col_map['timestamp']
        src_col = col_map['source_ip']
        query_col = col_map['query_name']
        type_col = col_map['query_type']
        size_col = col_map['response_size']
        
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df[ts_col]):
            df[ts_col] = pd.to_datetime(df[ts_col], errors='coerce')
        
        results = []
        
        # Group by source IP and base domain
        for src_ip, group in df.groupby(src_col):
            if pd.isna(src_ip) or src_ip == '':
                continue
            
            score = 0
            flags = []
            
            # Extract base domains
            queries = group[query_col].dropna().astype(str)
            if len(queries) == 0:
                continue
            
            # Calculate subdomain statistics
            subdomain_lengths = []
            base64_like = 0
            hex_like = 0
            long_subdomains = 0
            
            for query in queries:
                parts = query.split('.')
                if len(parts) > 2:
                    subdomain = parts[0]
                    subdomain_lengths.append(len(subdomain))
                    
                    # Check for base64-like encoding
                    if len(subdomain) > 10 and re.match(r'^[A-Za-z0-9+/=]+$', subdomain):
                        base64_like += 1
                    
                    # Check for hex encoding
                    if len(subdomain) > 10 and re.match(r'^[0-9a-fA-F]+$', subdomain):
                        hex_like += 1
                    
                    # Check for suspiciously long subdomains
                    if len(subdomain) > 40:
                        long_subdomains += 1
            
            # Analyze subdomain length patterns
            if len(subdomain_lengths) > 0:
                avg_length = np.mean(subdomain_lengths)
                std_length = np.std(subdomain_lengths)
                
                if avg_length > 30:
                    score += 25
                    flags.append('long_subdomains')
                
                if std_length < 5 and avg_length > 20:
                    score += 20
                    flags.append('consistent_encoding')
            
            # Check for encoding patterns
            if base64_like > len(queries) * 0.3:
                score += 30
                flags.append('base64_encoding')
            
            if hex_like > len(queries) * 0.3:
                score += 30
                flags.append('hex_encoding')
            
            # Check query volume
            query_count = len(group)
            if query_count > 100:
                score += 20
                flags.append('high_volume')
            
            # Check for TXT query abuse
            txt_queries = group[group[type_col].astype(str).str.upper() == 'TXT']
            if len(txt_queries) > 10:
                score += 25
                flags.append('txt_record_abuse')
            
            # Check response sizes (large responses may indicate data return)
            if pd.api.types.is_numeric_dtype(group[size_col]):
                large_responses = group[group[size_col] > 512]
                if len(large_responses) > 5:
                    score += 15
                    flags.append('large_responses')
            
            # Check for burst patterns
            if len(group) > 10:
                time_diffs = group.sort_values(ts_col)[ts_col].diff().dt.total_seconds().dropna()
                if len(time_diffs) > 0 and time_diffs.median() < 1:
                    score += 20
                    flags.append('burst_pattern')
            
            if score >= 50:  # Only report likely exfiltration
                results.append({
                    'source_ip': src_ip,
                    'query_count': query_count,
                    'avg_subdomain_length': np.mean(subdomain_lengths) if subdomain_lengths else 0,
                    'base64_like_queries': base64_like,
                    'hex_like_queries': hex_like,
                    'txt_queries': len(txt_queries),
                    'first_query': group[ts_col].min(),
                    'last_query': group[ts_col].max(),
                    'unique_domains': group[query_col].nunique(),
                    'flags': ', '.join(set(flags)),
                    'exfiltration_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('exfiltration_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate DNS exfiltration visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Scatter plot of query volume vs score
        fig = go.Figure(go.Scatter(
            x=result_df['query_count'],
            y=result_df['exfiltration_score'],
            mode='markers',
            marker=dict(
                size=result_df['avg_subdomain_length'],
                color=result_df['exfiltration_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Exfil Score"),
                line=dict(width=1, color='darkred')
            ),
            text=result_df['source_ip'],
            hovertemplate='<b>%{text}</b><br>Queries: %{x}<br>Score: %{y}<br>Avg Length: %{marker.size:.1f}<extra></extra>'
        ))
        
        fig.update_layout(
            title='DNS Exfiltration: Query Volume vs Risk Score',
            xaxis_title='Query Count',
            yaxis_title='Exfiltration Score',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for DNSExfiltrationStrategy output columns."""
        return {
            'source_ip': 'Source IP conducting suspicious DNS queries',
            'query_count': 'Total number of DNS queries from this source',
            'avg_subdomain_length': 'Average length of subdomains (longer suggests encoding)',
            'base64_like_queries': 'Count of queries with base64-like patterns',
            'hex_like_queries': 'Count of queries with hexadecimal encoding',
            'txt_queries': 'Number of TXT record queries (common for exfiltration)',
            'first_query': 'First suspicious query timestamp',
            'last_query': 'Most recent query timestamp',
            'unique_domains': 'Number of unique domains queried',
            'flags': 'Exfiltration indicators (base64_encoding, txt_record_abuse, burst_pattern, etc.)',
            'exfiltration_score': 'DNS exfiltration risk score (0-100). Scores ≥75 indicate active data exfiltration. Scores ≥50 warrant immediate investigation and network isolation'
        }


class ProcessInjectionStrategy(HuntStrategy):
    """
    Detect process injection and code injection attacks.
    
    Identifies suspicious process manipulation including DLL injection,
    process hollowing, thread injection, and reflective loading. Critical
    for detecting advanced malware and post-exploitation techniques.
    """
    
    INJECTION_APIS = [
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
        'SetWindowsHookEx', 'QueueUserAPC', 'NtMapViewOfSection',
        'RtlCreateUserThread', 'ZwUnmapViewOfSection'
    ]
    
    SUSPICIOUS_PROCESSES = [
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
        'regsvr32.exe', 'rundll32.exe', 'mshta.exe', 'wmic.exe'
    ]
    
    def _get_name(self) -> str:
        return "Process Injection Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_process', 'target_process', 'api_call', 'parent_process']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """Analyze process activity for injection attacks."""
        
        # Map columns
        ts_col = col_map['timestamp']
        src_proc_col = col_map['source_process']
        tgt_proc_col = col_map['target_process']
        api_col = col_map['api_call']
        parent_col = col_map['parent_process']
        
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df[ts_col]):
            df[ts_col] = pd.to_datetime(df[ts_col], errors='coerce')
        
        results = []
        
        # Group by source and target process
        for (src_proc, tgt_proc), group in df.groupby([src_proc_col, tgt_proc_col]):
            if pd.isna(src_proc) or pd.isna(tgt_proc) or src_proc == tgt_proc:
                continue
            
            score = 0
            flags = []
            injection_apis = []
            
            src_lower = str(src_proc).lower()
            tgt_lower = str(tgt_proc).lower()
            
            # Check if source is suspicious
            if any(susp in src_lower for susp in self.SUSPICIOUS_PROCESSES):
                score += 20
                flags.append('suspicious_source')
            
            # Check for injection API calls
            api_calls = group[api_col].dropna().astype(str)
            for api_call in api_calls:
                for inj_api in self.INJECTION_APIS:
                    if inj_api.lower() in api_call.lower():
                        score += 15
                        injection_apis.append(inj_api)
                        flags.append('injection_api')
                        break
            
            # Check for cross-process memory operations
            if len(injection_apis) > 0:
                if 'WriteProcessMemory' in injection_apis and 'CreateRemoteThread' in injection_apis:
                    score += 30
                    flags.append('classic_injection')
                
                if 'VirtualAllocEx' in injection_apis:
                    score += 25
                    flags.append('memory_allocation')
            
            # Check parent-child relationship anomalies
            parents = group[parent_col].unique()
            if len(parents) > 0:
                parent = str(parents[0]).lower()
                # Suspicious if parent is not typical
                if any(x in parent for x in ['explorer.exe', 'services.exe', 'lsass.exe']):
                    if any(susp in src_lower for susp in self.SUSPICIOUS_PROCESSES):
                        score += 15
                        flags.append('suspicious_parent')
            
            # Check for rapid injection attempts
            if len(group) > 10:
                score += 20
                flags.append('multiple_attempts')
            
            # Check for injection into system processes
            system_targets = ['lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 'svchost.exe']
            if any(sys_proc in tgt_lower for sys_proc in system_targets):
                score += 25
                flags.append('system_process_target')
            
            if score >= 50:  # Only report significant injection attempts
                results.append({
                    'source_process': src_proc,
                    'target_process': tgt_proc,
                    'parent_process': parents[0] if len(parents) > 0 else 'Unknown',
                    'api_calls': len(group),
                    'injection_apis': ', '.join(list(set(injection_apis))[:5]),
                    'first_seen': group[ts_col].min(),
                    'last_seen': group[ts_col].max(),
                    'flags': ', '.join(set(flags)),
                    'injection_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('injection_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate process injection visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Network graph of injection relationships would be ideal, but use bar chart for simplicity
        top_injections = result_df.nlargest(15, 'injection_score')
        
        labels = [f"{row['source_process']} → {row['target_process']}" 
                 for _, row in top_injections.iterrows()]
        
        fig = go.Figure(go.Bar(
            x=top_injections['injection_score'],
            y=labels,
            orientation='h',
            marker=dict(
                color=top_injections['injection_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Injection Score")
            ),
            text=top_injections['api_calls'],
            textposition='auto',
            hovertemplate='<b>%{y}</b><br>Score: %{x}<br>API Calls: %{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Process Injection Attacks',
            xaxis_title='Process Injection Risk Score',
            yaxis_title='Source → Target Process',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for ProcessInjectionStrategy output columns."""
        return {
            'source_process': 'Process attempting to inject code',
            'target_process': 'Process being targeted for injection',
            'parent_process': 'Parent process of the source process',
            'api_calls': 'Total number of API calls detected',
            'injection_apis': 'Specific Windows APIs used for injection',
            'first_seen': 'First injection attempt timestamp',
            'last_seen': 'Most recent injection attempt timestamp',
            'flags': 'Injection indicators (classic_injection, system_process_target, suspicious_source, etc.)',
            'injection_score': 'Process injection risk score (0-100). Scores ≥75 indicate active code injection requiring immediate investigation. Scores ≥50 suggest reconnaissance or preparation'
        }


class LiveOffLandStrategy(HuntStrategy):
    """
    Detect living-off-the-land (LOLBin) abuse patterns.
    
    Identifies abuse of legitimate system binaries for malicious purposes,
    including proxy execution, download cradles, and evasion techniques.
    Focuses on advanced LOLBin techniques beyond basic fileless detection.
    """
    
    LOLBIN_PATTERNS = {
        'certutil': ['urlcache', 'verifyctl', 'decode', '-split'],
        'bitsadmin': ['/transfer', '/create', '/addfile', '/download'],
        'powershell': ['-enc', '-windowstyle hidden', 'downloadstring', 'invoke-expression', 'bypass'],
        'rundll32': ['javascript:', 'vbscript:', 'url.dll', 'setupapi.dll'],
        'regsvr32': ['/s', '/u', '/i:', 'scrobj.dll'],
        'mshta': ['javascript:', 'vbscript:', 'http'],
        'wmic': ['process call create', '/format:', 'xsl'],
        'cscript': ['//b', '//nologo'],
        'regasm': ['/u'],
        'installutil': ['/logfile=', '/u']
    }
    
    def _get_name(self) -> str:
        return "Living-off-the-Land Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'username', 'process_name', 'command_line']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """Analyze command execution for LOLBin abuse."""
        
        # Map columns
        ts_col = col_map['timestamp']
        src_col = col_map['source_ip']
        user_col = col_map['username']
        proc_col = col_map['process_name']
        cmd_col = col_map['command_line']
        
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df[ts_col]):
            df[ts_col] = pd.to_datetime(df[ts_col], errors='coerce')
        
        results = []
        
        # Group by source IP and username
        for (src_ip, username), group in df.groupby([src_col, user_col]):
            if pd.isna(src_ip) and pd.isna(username):
                continue
            
            score = 0
            flags = []
            lolbins_used = set()
            technique_count = 0
            
            for _, row in group.iterrows():
                proc = str(row[proc_col]).lower() if pd.notna(row[proc_col]) else ''
                cmd = str(row[cmd_col]).lower() if pd.notna(row[cmd_col]) else ''
                
                # Check for LOLBin usage
                for lolbin, patterns in self.LOLBIN_PATTERNS.items():
                    if lolbin in proc or lolbin in cmd:
                        lolbins_used.add(lolbin)
                        
                        # Check for specific malicious patterns
                        for pattern in patterns:
                            if pattern.lower() in cmd:
                                score += 15
                                technique_count += 1
                                flags.append(f'{lolbin}_abuse')
                                break
            
            # Multiple LOLBins suggest orchestrated attack
            if len(lolbins_used) > 2:
                score += 25
                flags.append('multiple_lolbins')
            
            # High technique diversity
            if technique_count > 5:
                score += 20
                flags.append('varied_techniques')
            
            # Check for obfuscation
            for _, row in group.iterrows():
                cmd = str(row[cmd_col]) if pd.notna(row[cmd_col]) else ''
                if any(x in cmd for x in ['^', '`', '++', '${', '%']):
                    score += 15
                    flags.append('obfuscation')
                    break
            
            # Check for download cradle patterns
            download_indicators = ['downloadstring', 'downloadfile', 'webrequest', 'webclient', 'invoke-webrequest']
            for _, row in group.iterrows():
                cmd = str(row[cmd_col]).lower() if pd.notna(row[cmd_col]) else ''
                if any(dl in cmd for dl in download_indicators):
                    score += 25
                    flags.append('download_cradle')
                    break
            
            if score >= 40:  # Report LOLBin abuse
                results.append({
                    'source_ip': src_ip if pd.notna(src_ip) else 'Unknown',
                    'username': username if pd.notna(username) else 'Unknown',
                    'total_executions': len(group),
                    'lolbins_used': ', '.join(sorted(lolbins_used)),
                    'technique_count': technique_count,
                    'first_execution': group[ts_col].min(),
                    'last_execution': group[ts_col].max(),
                    'flags': ', '.join(set(flags)),
                    'lolbin_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('lolbin_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate LOLBin abuse visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Top users/IPs by LOLBin abuse score
        top_abusers = result_df.nlargest(15, 'lolbin_score')
        
        labels = [f"{row['username']} ({row['source_ip']})" 
                 for _, row in top_abusers.iterrows()]
        
        fig = go.Figure(go.Bar(
            x=top_abusers['lolbin_score'],
            y=labels,
            orientation='h',
            marker=dict(
                color=top_abusers['lolbin_score'],
                colorscale='YlOrRd',
                showscale=True,
                colorbar=dict(title="LOLBin Score")
            ),
            text=top_abusers['technique_count'],
            textposition='auto',
            hovertemplate='<b>%{y}</b><br>Score: %{x}<br>Techniques: %{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Living-off-the-Land (LOLBin) Abuse',
            xaxis_title='LOLBin Abuse Score',
            yaxis_title='Username (Source IP)',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for LiveOffLandStrategy output columns."""
        return {
            'source_ip': 'Source IP address executing LOLBin commands',
            'username': 'User account performing LOLBin abuse',
            'total_executions': 'Total number of suspicious executions',
            'lolbins_used': 'List of legitimate binaries abused (certutil, bitsadmin, etc.)',
            'technique_count': 'Number of distinct malicious techniques detected',
            'first_execution': 'First LOLBin abuse timestamp',
            'last_execution': 'Most recent LOLBin abuse timestamp',
            'flags': 'Abuse indicators (download_cradle, obfuscation, multiple_lolbins, etc.)',
            'lolbin_score': 'LOLBin abuse risk score (0-100). Scores ≥75 indicate active malicious use of system tools. Scores ≥50 require investigation for post-exploitation activity'
        }


class OAuthAbuseStrategy(HuntStrategy):
    """
    Detect OAuth token theft and refresh token abuse.
    
    Identifies suspicious OAuth flows including token replay attacks,
    refresh token abuse, excessive token requests, and authorization
    code interception. Essential for securing modern API authentication.
    """
    
    SUSPICIOUS_SCOPES = [
        'offline_access', 'full_control', 'admin', 'root',
        'mail.read', 'files.readwrite.all', 'user.read.all'
    ]
    
    def _get_name(self) -> str:
        return "OAuth Abuse Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'username', 'grant_type', 'scope']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """Analyze OAuth flows for abuse patterns."""
        
        # Map columns
        ts_col = col_map['timestamp']
        src_col = col_map['source_ip']
        user_col = col_map['username']
        grant_col = col_map['grant_type']
        scope_col = col_map['scope']
        
        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df[ts_col]):
            df[ts_col] = pd.to_datetime(df[ts_col], errors='coerce')
        
        results = []
        
        # Group by username
        for username, group in df.groupby(user_col):
            if pd.isna(username) or username == '':
                continue
            
            score = 0
            flags = []
            
            # Count token requests by type
            grant_types = group[grant_col].value_counts().to_dict()
            refresh_count = grant_types.get('refresh_token', 0)
            auth_code_count = grant_types.get('authorization_code', 0)
            
            # Check for excessive refresh token usage
            if refresh_count > 100:
                score += 30
                flags.append('excessive_refresh')
            elif refresh_count > 50:
                score += 20
                flags.append('high_refresh_rate')
            
            # Check for suspicious scopes
            scopes = group[scope_col].dropna().astype(str)
            dangerous_scopes = []
            for scope_str in scopes:
                for susp_scope in self.SUSPICIOUS_SCOPES:
                    if susp_scope in scope_str.lower():
                        dangerous_scopes.append(susp_scope)
                        score += 15
                        flags.append('dangerous_scope')
                        break
            
            # Check for multiple source IPs (token replay)
            unique_ips = group[src_col].nunique()
            if unique_ips > 10:
                score += 35
                flags.append('token_replay')
            elif unique_ips > 5:
                score += 20
                flags.append('multiple_locations')
            
            # Check for rapid token requests
            if len(group) > 20:
                time_diffs = group.sort_values(ts_col)[ts_col].diff().dt.total_seconds().dropna()
                if len(time_diffs) > 0 and time_diffs.median() < 10:
                    score += 25
                    flags.append('rapid_requests')
            
            # Check for authorization code grant abuse
            if auth_code_count > 20:
                score += 20
                flags.append('auth_code_abuse')
            
            # Check for geographically dispersed access
            source_ips = group[src_col].unique()
            if len(source_ips) > 0:
                # Simple heuristic: different /24 networks
                networks = set()
                for ip in source_ips:
                    if pd.notna(ip) and '.' in str(ip):
                        parts = str(ip).split('.')
                        if len(parts) >= 3:
                            networks.add('.'.join(parts[:3]))
                
                if len(networks) > 5:
                    score += 20
                    flags.append('geo_dispersed')
            
            if score >= 50:  # Only report significant OAuth abuse
                results.append({
                    'username': username,
                    'total_requests': len(group),
                    'refresh_token_count': refresh_count,
                    'unique_source_ips': unique_ips,
                    'dangerous_scopes': ', '.join(list(set(dangerous_scopes))[:5]) if dangerous_scopes else 'None',
                    'first_request': group[ts_col].min(),
                    'last_request': group[ts_col].max(),
                    'source_ips': ', '.join(map(str, source_ips[:3])),
                    'flags': ', '.join(set(flags)),
                    'oauth_abuse_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('oauth_abuse_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate OAuth abuse visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Scatter plot: refresh token count vs unique IPs
        fig = go.Figure(go.Scatter(
            x=result_df['refresh_token_count'],
            y=result_df['unique_source_ips'],
            mode='markers',
            marker=dict(
                size=result_df['total_requests'] / 10,
                color=result_df['oauth_abuse_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="OAuth Abuse Score"),
                line=dict(width=1, color='darkred')
            ),
            text=result_df['username'],
            hovertemplate='<b>%{text}</b><br>Refresh Tokens: %{x}<br>Unique IPs: %{y}<br>Score: %{marker.color}<extra></extra>'
        ))
        
        fig.update_layout(
            title='OAuth Abuse: Token Requests vs Source Diversity',
            xaxis_title='Refresh Token Count',
            yaxis_title='Unique Source IPs',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for OAuthAbuseStrategy output columns."""
        return {
            'username': 'User account with suspicious OAuth activity',
            'total_requests': 'Total OAuth token requests',
            'refresh_token_count': 'Number of refresh token grant requests',
            'unique_source_ips': 'Count of unique source IPs (higher = potential token theft)',
            'dangerous_scopes': 'High-privilege scopes requested',
            'first_request': 'First OAuth request timestamp',
            'last_request': 'Most recent OAuth request timestamp',
            'source_ips': 'Sample of source IP addresses',
            'flags': 'Abuse indicators (token_replay, excessive_refresh, dangerous_scope, etc.)',
            'oauth_abuse_score': 'OAuth abuse risk score (0-100). Scores ≥75 indicate likely stolen tokens requiring immediate revocation. Scores ≥50 suggest compromise investigation needed'
        }


class InsiderThreatStrategy(HuntStrategy):
    """
    Detects insider threat indicators based on behavioral anomalies.
    
    Monitors for:
    - Unusual data access patterns (accessing more resources than typical)
    - After-hours access combined with bulk downloads
    - Access to sensitive resources before resignation/termination
    - Behavioral changes (sudden increase in file access, database queries, etc.)
    - Access to data outside normal job function
    """
    
    def _get_name(self) -> str:
        return "Insider Threat Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'username', 'source_ip', 'resource_accessed', 'bytes_transferred']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """Analyze for insider threat indicators."""
        if df.empty:
            return pd.DataFrame()
        
        ts_col = col_map.get('timestamp')
        user_col = col_map.get('username')
        src_col = col_map.get('source_ip')
        resource_col = col_map.get('resource_accessed')
        bytes_col = col_map.get('bytes_transferred')
        
        # Convert timestamp to datetime if needed
        if ts_col and ts_col in df.columns:
            df[ts_col] = pd.to_datetime(df[ts_col], errors='coerce')
        
        results = []
        
        # Analyze per user
        for username, group in df.groupby(user_col):
            if pd.isna(username):
                continue
            
            score = 0
            flags = []
            
            # Check for off-hours access (weekends, 6pm-6am)
            off_hours_count = 0
            if ts_col and ts_col in group.columns:
                for ts in group[ts_col]:
                    if pd.notna(ts):
                        # Weekend
                        if ts.dayofweek >= 5:
                            off_hours_count += 1
                        # Late night/early morning (6pm to 6am)
                        elif ts.hour >= 18 or ts.hour < 6:
                            off_hours_count += 1
            
            off_hours_ratio = off_hours_count / len(group) if len(group) > 0 else 0
            if off_hours_ratio > 0.3:  # >30% off-hours activity
                score += 25
                flags.append('excessive_off_hours')
            
            # Check for unusual volume of resource access
            unique_resources = group[resource_col].nunique()
            if unique_resources > 50:
                score += 20
                flags.append('excessive_resource_access')
            if unique_resources > 100:
                score += 15
                flags.append('very_high_resource_access')
            
            # Check for bulk data transfer
            if bytes_col and bytes_col in group.columns:
                total_bytes = group[bytes_col].sum()
                if total_bytes > 10 * 1024 * 1024 * 1024:  # >10GB
                    score += 25
                    flags.append('bulk_data_transfer')
                elif total_bytes > 5 * 1024 * 1024 * 1024:  # >5GB
                    score += 15
                    flags.append('high_data_transfer')
            
            # Check for rapid sequential access (potential automated scraping)
            if ts_col and len(group) > 10:
                time_diffs = group[ts_col].diff().dt.total_seconds()
                rapid_access = (time_diffs < 5).sum()  # Less than 5 sec between requests
                if rapid_access / len(group) > 0.5:  # >50% rapid access
                    score += 20
                    flags.append('automated_access_pattern')
            
            # Check for access from multiple IPs (potential credential sharing)
            unique_ips = group[src_col].nunique()
            if unique_ips > 5:
                score += 20
                flags.append('multiple_source_ips')
            
            # Check for sensitive resource patterns
            sensitive_patterns = ['confidential', 'secret', 'financial', 'payroll', 'hr', 'salary', 'ssn', 'password', 'credential']
            sensitive_access = 0
            for resource in group[resource_col]:
                if pd.notna(resource):
                    resource_lower = str(resource).lower()
                    if any(pattern in resource_lower for pattern in sensitive_patterns):
                        sensitive_access += 1
            
            if sensitive_access > 10:
                score += 30
                flags.append('sensitive_data_access')
            
            if score >= 40:  # Only report significant insider threats
                results.append({
                    'username': username,
                    'total_accesses': len(group),
                    'unique_resources': unique_resources,
                    'unique_source_ips': unique_ips,
                    'off_hours_ratio': round(off_hours_ratio, 2),
                    'total_bytes_transferred': group[bytes_col].sum() if bytes_col in group.columns else 0,
                    'sensitive_access_count': sensitive_access,
                    'first_access': group[ts_col].min() if ts_col in group.columns else None,
                    'last_access': group[ts_col].max() if ts_col in group.columns else None,
                    'source_ips': ', '.join(map(str, group[src_col].unique()[:3])),
                    'flags': ', '.join(set(flags)),
                    'insider_threat_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('insider_threat_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate insider threat visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Scatter plot: resource access vs data transferred
        fig = go.Figure(go.Scatter(
            x=result_df['unique_resources'],
            y=result_df['total_bytes_transferred'],
            mode='markers',
            marker=dict(
                size=result_df['total_accesses'] / 10,
                color=result_df['insider_threat_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Threat Score"),
                line=dict(width=1, color='darkred')
            ),
            text=result_df['username'],
            hovertemplate='<b>%{text}</b><br>Resources: %{x}<br>Bytes: %{y}<br>Score: %{marker.color}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Insider Threat: Resource Access vs Data Transfer',
            xaxis_title='Unique Resources Accessed',
            yaxis_title='Total Bytes Transferred',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for InsiderThreatStrategy output columns."""
        return {
            'username': 'User account showing insider threat indicators',
            'total_accesses': 'Total number of resource access events',
            'unique_resources': 'Number of unique resources accessed (higher = broader data collection)',
            'unique_source_ips': 'Number of unique source IPs (multiple IPs may indicate credential sharing)',
            'off_hours_ratio': 'Ratio of off-hours access (weekends, 6pm-6am). Values >0.3 are suspicious',
            'total_bytes_transferred': 'Total data transferred in bytes',
            'sensitive_access_count': 'Number of accesses to sensitive resources (confidential, financial, etc.)',
            'first_access': 'First access timestamp in the analysis window',
            'last_access': 'Most recent access timestamp',
            'source_ips': 'Sample of source IP addresses used',
            'flags': 'Threat indicators (excessive_off_hours, bulk_data_transfer, sensitive_data_access, etc.)',
            'insider_threat_score': 'Insider threat risk score (0-100). Scores ≥75 require immediate investigation. Scores ≥50 suggest heightened monitoring'
        }


class RansomwareBehaviorStrategy(HuntStrategy):
    """
    Detects real-time ransomware-like file operations.
    
    Monitors for:
    - Mass file operations (rapid create/modify/delete)
    - File extension changes (encryption indicators)
    - Shadow copy deletion commands
    - Backup service tampering
    - Ransom note file creation (.txt, .html with ransom keywords)
    - High entropy file creations (encrypted files)
    """
    
    def _get_name(self) -> str:
        return "Ransomware Behavior Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'process_name', 'file_path', 'operation']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """Analyze for ransomware behavior patterns."""
        if df.empty:
            return pd.DataFrame()
        
        ts_col = col_map.get('timestamp')
        src_col = col_map.get('source_ip')
        process_col = col_map.get('process_name')
        file_col = col_map.get('file_path')
        op_col = col_map.get('operation')
        
        # Convert timestamp to datetime if needed
        if ts_col and ts_col in df.columns:
            df[ts_col] = pd.to_datetime(df[ts_col], errors='coerce')
        
        results = []
        
        # Ransomware file extensions
        ransomware_extensions = [
            '.encrypted', '.locked', '.crypto', '.crypt', '.cerber', '.locky',
            '.zepto', '.osiris', '.thor', '.aesir', '.zzzzz', '.abc', '.xyz',
            '.wallet', '.onion', '.wncry', '.wcry', '.cryptolocker'
        ]
        
        # Ransom note patterns
        ransom_note_patterns = ['readme', 'decrypt', 'recover', 'restore', 'how_to', 'instruction']
        
        # Analyze per source
        for source, group in df.groupby(src_col):
            if pd.isna(source):
                continue
            
            score = 0
            flags = []
            
            # Check for mass file operations
            time_window = timedelta(minutes=5)
            if ts_col and ts_col in group.columns:
                max_ops_in_window = 0
                for ts in group[ts_col].dropna():
                    window_end = ts + time_window
                    ops_in_window = ((group[ts_col] >= ts) & (group[ts_col] <= window_end)).sum()
                    max_ops_in_window = max(max_ops_in_window, ops_in_window)
                
                if max_ops_in_window > 100:
                    score += 35
                    flags.append('mass_file_operations')
                elif max_ops_in_window > 50:
                    score += 20
                    flags.append('high_file_activity')
            
            # Check for suspicious file extensions
            ransomware_files = 0
            if file_col and file_col in group.columns:
                for file_path in group[file_col]:
                    if pd.notna(file_path):
                        file_str = str(file_path).lower()
                        if any(ext in file_str for ext in ransomware_extensions):
                            ransomware_files += 1
            
            if ransomware_files > 10:
                score += 40
                flags.append('ransomware_extensions')
            elif ransomware_files > 0:
                score += 20
                flags.append('suspicious_extensions')
            
            # Check for ransom note creation
            ransom_notes = 0
            if file_col and file_col in group.columns:
                for file_path in group[file_col]:
                    if pd.notna(file_path):
                        file_str = str(file_path).lower()
                        if any(pattern in file_str for pattern in ransom_note_patterns):
                            if file_str.endswith(('.txt', '.html', '.htm')):
                                ransom_notes += 1
            
            if ransom_notes > 0:
                score += 35
                flags.append('ransom_note_creation')
            
            # Check for shadow copy deletion
            shadow_copy_cmds = ['vssadmin', 'wbadmin', 'bcdedit', 'wmic shadowcopy']
            if process_col and process_col in group.columns:
                for process in group[process_col]:
                    if pd.notna(process):
                        process_str = str(process).lower()
                        if any(cmd in process_str for cmd in shadow_copy_cmds):
                            if 'delete' in process_str or 'shadows' in process_str:
                                score += 30
                                flags.append('shadow_copy_deletion')
                                break
            
            # Check for backup service tampering
            backup_keywords = ['backup', 'vss', 'shadow', 'restore']
            if process_col and op_col:
                if process_col in group.columns and op_col in group.columns:
                    for idx, row in group.iterrows():
                        process_str = str(row[process_col]).lower() if pd.notna(row[process_col]) else ''
                        op_str = str(row[op_col]).lower() if pd.notna(row[op_col]) else ''
                        
                        if any(kw in process_str for kw in backup_keywords):
                            if 'stop' in op_str or 'disable' in op_str or 'delete' in op_str:
                                score += 25
                                flags.append('backup_tampering')
                                break
            
            # Check for multiple file extensions being changed
            if file_col and file_col in group.columns:
                original_extensions = set()
                for file_path in group[file_col]:
                    if pd.notna(file_path) and '.' in str(file_path):
                        ext = str(file_path).rsplit('.', 1)[-1]
                        original_extensions.add(ext)
                
                if len(original_extensions) > 20:
                    score += 25
                    flags.append('mass_extension_changes')
            
            if score >= 50:  # Only report significant ransomware behavior
                results.append({
                    'source_ip': source,
                    'total_file_operations': len(group),
                    'ransomware_extension_count': ransomware_files,
                    'ransom_note_count': ransom_notes,
                    'first_operation': group[ts_col].min() if ts_col in group.columns else None,
                    'last_operation': group[ts_col].max() if ts_col in group.columns else None,
                    'unique_processes': group[process_col].nunique() if process_col in group.columns else 0,
                    'flags': ', '.join(set(flags)),
                    'ransomware_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('ransomware_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate ransomware behavior visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Bar chart of ransomware scores
        fig = go.Figure(go.Bar(
            x=result_df['source_ip'],
            y=result_df['ransomware_score'],
            marker=dict(
                color=result_df['ransomware_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Score")
            ),
            text=result_df['ransomware_score'],
            textposition='outside',
            hovertemplate='<b>%{x}</b><br>Score: %{y}<br><extra></extra>'
        ))
        
        fig.update_layout(
            title='Ransomware Behavior Detection Scores by Source',
            xaxis_title='Source IP',
            yaxis_title='Ransomware Score',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for RansomwareBehaviorStrategy output columns."""
        return {
            'source_ip': 'Source IP showing ransomware-like behavior',
            'total_file_operations': 'Total number of file operations performed',
            'ransomware_extension_count': 'Number of files with ransomware-associated extensions',
            'ransom_note_count': 'Number of potential ransom note files created',
            'first_operation': 'First file operation timestamp',
            'last_operation': 'Most recent file operation timestamp',
            'unique_processes': 'Number of unique processes involved',
            'flags': 'Behavior indicators (mass_file_operations, shadow_copy_deletion, ransom_note_creation, etc.)',
            'ransomware_score': 'Ransomware behavior risk score (0-100). Scores ≥75 indicate active ransomware requiring immediate containment. Scores ≥50 suggest investigation needed'
        }


class ZeroDayExploitStrategy(HuntStrategy):
    """
    Detects potential zero-day exploitation attempts.
    
    Monitors for:
    - Unusual protocol violations or malformed packets
    - Exploitation frameworks (Metasploit, Cobalt Strike signatures)
    - Unusual shellcode patterns in network traffic
    - Abnormal memory access patterns
    - Crashes followed by successful execution
    - Privilege changes after suspicious operations
    """
    
    def _get_name(self) -> str:
        return "Zero-Day Exploit Indicator"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'destination_ip', 'protocol', 'payload']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """Analyze for zero-day exploitation indicators."""
        if df.empty:
            return pd.DataFrame()
        
        ts_col = col_map.get('timestamp')
        src_col = col_map.get('source_ip')
        dst_col = col_map.get('destination_ip')
        proto_col = col_map.get('protocol')
        payload_col = col_map.get('payload')
        
        results = []
        
        # Exploitation framework signatures
        exploit_signatures = [
            'metasploit', 'meterpreter', 'cobalt', 'beacon', 'stager',
            'shellcode', 'exploit', 'payload', '/admin/exploit',
            'msf', 'venom', 'pwn', '\\x90\\x90\\x90',  # NOP sled
            'shikata_ga_nai'  # Metasploit encoder
        ]
        
        # Shellcode patterns
        shellcode_patterns = [
            '\\x90\\x90',  # NOP sled
            '\\xeb\\x',  # JMP short
            '\\xe8\\x',  # CALL
            '\\x31\\xc0',  # XOR EAX, EAX
            '\\x48\\x31',  # XOR (x64)
            '\\xcc',  # INT3 (breakpoint)
        ]
        
        # Analyze per source-destination pair
        for (source, dest), group in df.groupby([src_col, dst_col]):
            if pd.isna(source) or pd.isna(dest):
                continue
            
            score = 0
            flags = []
            
            # Check for exploitation framework signatures
            exploit_hits = 0
            if payload_col and payload_col in group.columns:
                for payload in group[payload_col]:
                    if pd.notna(payload):
                        payload_str = str(payload).lower()
                        if any(sig in payload_str for sig in exploit_signatures):
                            exploit_hits += 1
            
            if exploit_hits > 0:
                score += 40
                flags.append('exploit_framework_detected')
            
            # Check for shellcode patterns
            shellcode_hits = 0
            if payload_col and payload_col in group.columns:
                for payload in group[payload_col]:
                    if pd.notna(payload):
                        payload_str = str(payload)
                        if any(pattern in payload_str for pattern in shellcode_patterns):
                            shellcode_hits += 1
            
            if shellcode_hits > 0:
                score += 35
                flags.append('shellcode_pattern')
            
            # Check for unusual payload sizes (very large or very specific sizes)
            if payload_col and payload_col in group.columns:
                payload_lengths = [len(str(p)) for p in group[payload_col] if pd.notna(p)]
                if payload_lengths:
                    max_len = max(payload_lengths)
                    if max_len > 10000:  # Very large payload
                        score += 25
                        flags.append('large_payload')
                    
                    # Check for multiple identical payload sizes (exploit repeatability)
                    size_counts = Counter(payload_lengths)
                    if size_counts.most_common(1)[0][1] > 5:  # Same size 5+ times
                        score += 20
                        flags.append('repeated_payload_size')
            
            # Check for protocol violations
            unusual_protocols = ['unknown', 'malformed', 'invalid', 'corrupt']
            if proto_col and proto_col in group.columns:
                for proto in group[proto_col]:
                    if pd.notna(proto):
                        proto_str = str(proto).lower()
                        if any(up in proto_str for up in unusual_protocols):
                            score += 30
                            flags.append('protocol_violation')
                            break
            
            # Check for rapid retries (exploitation attempts)
            if ts_col and ts_col in group.columns and len(group) > 5:
                df_sorted = group.sort_values(ts_col)
                df_sorted[ts_col] = pd.to_datetime(df_sorted[ts_col], errors='coerce')
                time_diffs = df_sorted[ts_col].diff().dt.total_seconds()
                rapid_retries = (time_diffs < 2).sum()  # Less than 2 sec between attempts
                
                if rapid_retries > 10:
                    score += 25
                    flags.append('rapid_exploitation_attempts')
            
            # Check for unusual payload entropy (encrypted/encoded exploits)
            if payload_col and payload_col in group.columns:
                high_entropy_count = 0
                for payload in group[payload_col]:
                    if pd.notna(payload) and len(str(payload)) > 10:
                        # Convert payload to byte counts for entropy calculation
                        payload_bytes = str(payload).encode('utf-8', errors='ignore')
                        byte_counts = [payload_bytes.count(bytes([i])) for i in range(256)]
                        byte_counts = [c for c in byte_counts if c > 0]  # Remove zeros
                        if byte_counts:
                            payload_entropy = entropy(byte_counts)
                            if payload_entropy > 7.0:  # High entropy
                                high_entropy_count += 1
                
                if high_entropy_count > 3:
                    score += 20
                    flags.append('high_entropy_payload')
            
            if score >= 50:  # Only report significant exploitation indicators
                results.append({
                    'source_ip': source,
                    'destination_ip': dest,
                    'total_attempts': len(group),
                    'exploit_signature_hits': exploit_hits,
                    'shellcode_hits': shellcode_hits,
                    'first_attempt': group[ts_col].min() if ts_col in group.columns else None,
                    'last_attempt': group[ts_col].max() if ts_col in group.columns else None,
                    'protocols': ', '.join(map(str, group[proto_col].unique()[:3])) if proto_col in group.columns else '',
                    'flags': ', '.join(set(flags)),
                    'exploit_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('exploit_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate zero-day exploit visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Network graph-style scatter
        fig = go.Figure(go.Scatter(
            x=result_df['source_ip'],
            y=result_df['destination_ip'],
            mode='markers',
            marker=dict(
                size=result_df['total_attempts'],
                color=result_df['exploit_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Exploit Score"),
                line=dict(width=1, color='darkred')
            ),
            text=result_df['flags'],
            hovertemplate='<b>%{x} → %{y}</b><br>Attempts: %{marker.size}<br>Score: %{marker.color}<br>Flags: %{text}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Zero-Day Exploitation Attempts',
            xaxis_title='Source IP',
            yaxis_title='Destination IP',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for ZeroDayExploitStrategy output columns."""
        return {
            'source_ip': 'Source IP of exploitation attempts',
            'destination_ip': 'Target IP being exploited',
            'total_attempts': 'Number of exploitation attempts observed',
            'exploit_signature_hits': 'Number of known exploitation framework signatures detected',
            'shellcode_hits': 'Number of shellcode patterns identified in payloads',
            'first_attempt': 'First exploitation attempt timestamp',
            'last_attempt': 'Most recent exploitation attempt timestamp',
            'protocols': 'Protocols used in exploitation attempts',
            'flags': 'Exploitation indicators (exploit_framework_detected, shellcode_pattern, protocol_violation, etc.)',
            'exploit_score': 'Exploitation risk score (0-100). Scores ≥75 indicate active exploitation requiring emergency response. Scores ≥50 suggest investigation and patching needed'
        }


class CloudMisconfigStrategy(HuntStrategy):
    """
    Detects cloud infrastructure misconfigurations and security issues.
    
    Monitors for:
    - Public S3 buckets and storage containers
    - Overly permissive IAM policies
    - Unencrypted storage
    - Missing MFA on privileged accounts
    - Open security groups (0.0.0.0/0 access)
    - Exposed credentials in code repositories
    """
    
    def _get_name(self) -> str:
        return "Cloud Misconfiguration Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'resource_type', 'resource_name', 'configuration', 'permissions']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """Analyze for cloud misconfigurations."""
        if df.empty:
            return pd.DataFrame()
        
        ts_col = col_map.get('timestamp')
        type_col = col_map.get('resource_type')
        name_col = col_map.get('resource_name')
        config_col = col_map.get('configuration')
        perm_col = col_map.get('permissions')
        
        results = []
        
        # Analyze each resource
        for idx, row in df.iterrows():
            resource_type = row[type_col] if type_col and type_col in row else None
            resource_name = row[name_col] if name_col and name_col in row else None
            configuration = row[config_col] if config_col and config_col in row else None
            permissions = row[perm_col] if perm_col and perm_col in row else None
            
            if pd.isna(resource_name):
                continue
            
            score = 0
            flags = []
            
            resource_type_str = str(resource_type).lower() if pd.notna(resource_type) else ''
            config_str = str(configuration).lower() if pd.notna(configuration) else ''
            perm_str = str(permissions).lower() if pd.notna(permissions) else ''
            
            # Check for public storage
            if any(term in resource_type_str for term in ['s3', 'bucket', 'storage', 'blob']):
                if any(term in config_str or term in perm_str for term in ['public', 'everyone', 'anonymous', '*']):
                    score += 40
                    flags.append('public_storage')
            
            # Check for wildcard permissions
            if '*' in perm_str or 'all' in perm_str or 'everyone' in perm_str:
                score += 35
                flags.append('wildcard_permissions')
            
            # Check for unencrypted resources
            if 'encrypt' not in config_str and 'encryption' not in config_str:
                if any(term in resource_type_str for term in ['storage', 'database', 'volume', 'disk']):
                    score += 30
                    flags.append('unencrypted_storage')
            
            # Check for open security groups (0.0.0.0/0)
            if 'security' in resource_type_str or 'firewall' in resource_type_str:
                if '0.0.0.0/0' in config_str or '0.0.0.0/0' in perm_str:
                    score += 35
                    flags.append('open_security_group')
            
            # Check for missing MFA
            if 'user' in resource_type_str or 'iam' in resource_type_str or 'account' in resource_type_str:
                if 'admin' in perm_str or 'root' in perm_str or 'superuser' in perm_str:
                    if 'mfa' not in config_str and 'multi-factor' not in config_str:
                        score += 30
                        flags.append('no_mfa_on_privileged_account')
            
            # Check for exposed credentials
            credential_keywords = ['password', 'secret', 'api_key', 'access_key', 'private_key', 'token']
            if any(kw in config_str for kw in credential_keywords):
                if 'hardcoded' in config_str or 'plaintext' in config_str or 'unencrypted' in config_str:
                    score += 40
                    flags.append('exposed_credentials')
            
            # Check for overly broad IAM policies
            if 'iam' in resource_type_str or 'role' in resource_type_str:
                dangerous_actions = ['*', 'full', 'admin', 'delete', 'destroy']
                if any(action in perm_str for action in dangerous_actions):
                    score += 25
                    flags.append('overly_permissive_iam')
            
            # Check for default passwords/credentials
            if any(term in config_str for term in ['default', 'password123', 'admin123', 'changeme']):
                score += 35
                flags.append('default_credentials')
            
            # Check for missing logging/monitoring
            if 'logging' not in config_str and 'audit' not in config_str:
                if any(term in resource_type_str for term in ['database', 'storage', 'compute', 'instance']):
                    score += 20
                    flags.append('logging_disabled')
            
            if score >= 40:  # Only report significant misconfigurations
                results.append({
                    'resource_name': resource_name,
                    'resource_type': resource_type,
                    'configuration': configuration if pd.notna(configuration) else 'N/A',
                    'permissions': permissions if pd.notna(permissions) else 'N/A',
                    'timestamp': row[ts_col] if ts_col and ts_col in row else None,
                    'flags': ', '.join(set(flags)),
                    'misconfiguration_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('misconfiguration_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate cloud misconfiguration visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Bar chart by resource type
        type_scores = result_df.groupby('resource_type')['misconfiguration_score'].mean().sort_values(ascending=False)
        
        fig = go.Figure(go.Bar(
            x=type_scores.index,
            y=type_scores.values,
            marker=dict(
                color=type_scores.values,
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Avg Score")
            ),
            text=[f"{v:.1f}" for v in type_scores.values],
            textposition='outside'
        ))
        
        fig.update_layout(
            title='Cloud Misconfiguration Scores by Resource Type',
            xaxis_title='Resource Type',
            yaxis_title='Average Misconfiguration Score',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for CloudMisconfigStrategy output columns."""
        return {
            'resource_name': 'Cloud resource with security misconfiguration',
            'resource_type': 'Type of cloud resource (S3, IAM, Security Group, etc.)',
            'configuration': 'Current configuration settings',
            'permissions': 'Current permission/access settings',
            'timestamp': 'When the misconfiguration was detected',
            'flags': 'Misconfiguration types (public_storage, wildcard_permissions, no_mfa_on_privileged_account, etc.)',
            'misconfiguration_score': 'Severity score (0-100). Scores ≥75 indicate critical security risks requiring immediate remediation. Scores ≥50 should be addressed promptly'
        }


class APIGatewayAbuseStrategy(HuntStrategy):
    """
    Detects API gateway abuse, including rate limit bypasses, GraphQL query abuse,
    REST API enumeration, and excessive API calls that may indicate scraping or DDoS.
    """
    
    def _get_name(self) -> str:
        return "API Gateway Abuse Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'endpoint', 'status_code', 'response_time']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze API traffic for gateway abuse patterns.
        
        Detects:
        - Excessive API calls (potential scraping/DDoS)
        - GraphQL query complexity abuse
        - REST API enumeration attempts
        - Rate limit bypass attempts
        - Abnormal response times (timing attacks)
        """
        ts_col = col_map.get('timestamp')
        ip_col = col_map.get('source_ip')
        endpoint_col = col_map.get('endpoint')
        status_col = col_map.get('status_code')
        time_col = col_map.get('response_time')
        
        results = []
        
        # Group by source IP and endpoint
        for (source_ip, endpoint), group in df.groupby([ip_col, endpoint_col]):
            if pd.isna(source_ip) or pd.isna(endpoint):
                continue
            
            call_count = len(group)
            
            # Skip if too few calls to analyze
            if call_count < 10:
                continue
            
            score = 0
            flags = []
            
            endpoint_str = str(endpoint).lower()
            
            # Calculate rate (calls per minute)
            if ts_col and ts_col in df.columns:
                time_span = (group[ts_col].max() - group[ts_col].min()).total_seconds()
                if time_span > 0:
                    calls_per_minute = (call_count / time_span) * 60
                    
                    # High rate of calls
                    if calls_per_minute > 100:
                        score += 35
                        flags.append('excessive_call_rate')
                    elif calls_per_minute > 50:
                        score += 20
                        flags.append('high_call_rate')
            
            # Check for GraphQL abuse
            if 'graphql' in endpoint_str or 'graph' in endpoint_str:
                # Look for complex queries (indicated by large response times or multiple queries)
                if time_col and time_col in group.columns:
                    avg_response_time = group[time_col].mean()
                    if avg_response_time > 5000:  # >5 seconds
                        score += 30
                        flags.append('graphql_complex_query')
                
                if call_count > 100:
                    score += 25
                    flags.append('graphql_query_flood')
            
            # Check for REST API enumeration
            status_codes = group[status_col].value_counts()
            error_count = sum(status_codes.get(code, 0) for code in [400, 401, 403, 404])
            error_rate = error_count / call_count if call_count > 0 else 0
            
            if error_rate > 0.5 and call_count > 50:
                score += 30
                flags.append('api_enumeration')
            
            # Check for rate limit bypass patterns (429 followed by successful calls)
            if status_col and status_col in group.columns:
                has_429 = 429 in status_codes
                has_success = 200 in status_codes or 201 in status_codes
                
                if has_429 and has_success:
                    # They got rate limited but kept trying and succeeded
                    score += 35
                    flags.append('rate_limit_bypass_attempt')
            
            # Check for timing attack patterns (very consistent response times)
            if time_col and time_col in group.columns:
                response_times = group[time_col].dropna()
                if len(response_times) > 10:
                    std_dev = response_times.std()
                    mean_time = response_times.mean()
                    
                    # Very low variance might indicate timing attacks
                    if mean_time > 0 and (std_dev / mean_time) < 0.1:
                        score += 25
                        flags.append('potential_timing_attack')
            
            # Check for excessive data extraction
            if call_count > 200:
                score += 20
                flags.append('data_scraping_suspected')
            
            # Check for admin/sensitive endpoint probing
            sensitive_paths = ['admin', 'config', 'settings', 'debug', 'internal', 'swagger', 'api-docs']
            if any(path in endpoint_str for path in sensitive_paths):
                score += 25
                flags.append('sensitive_endpoint_probing')
            
            if score >= 40:  # Only report significant abuse
                results.append({
                    'source_ip': source_ip,
                    'endpoint': endpoint,
                    'call_count': call_count,
                    'error_rate': f"{error_rate:.2%}",
                    'first_seen': group[ts_col].min() if ts_col and ts_col in df.columns else None,
                    'last_seen': group[ts_col].max() if ts_col and ts_col in df.columns else None,
                    'flags': ', '.join(set(flags)),
                    'abuse_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('abuse_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate API abuse visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Scatter plot of call count vs abuse score
        fig = go.Figure(go.Scatter(
            x=result_df['call_count'],
            y=result_df['abuse_score'],
            mode='markers',
            marker=dict(
                size=10,
                color=result_df['abuse_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Abuse Score")
            ),
            text=result_df['source_ip'],
            hovertemplate='<b>%{text}</b><br>Calls: %{x}<br>Score: %{y}<extra></extra>'
        ))
        
        fig.update_layout(
            title='API Gateway Abuse Pattern',
            xaxis_title='Call Count',
            yaxis_title='Abuse Score',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for APIGatewayAbuseStrategy output columns."""
        return {
            'source_ip': 'IP address making excessive API calls',
            'endpoint': 'API endpoint being targeted',
            'call_count': 'Total number of API calls made',
            'error_rate': 'Percentage of failed/error responses',
            'first_seen': 'First timestamp of abuse activity',
            'last_seen': 'Most recent timestamp of abuse activity',
            'flags': 'Abuse patterns detected (excessive_call_rate, graphql_query_flood, api_enumeration, rate_limit_bypass_attempt, timing_attack, data_scraping_suspected, sensitive_endpoint_probing)',
            'abuse_score': 'Severity score (0-100). Scores ≥75 indicate likely automated abuse. Scores ≥50 suggest suspicious API usage patterns'
        }


class KerberosAttackStrategy(HuntStrategy):
    """
    Detects Kerberos-based attacks including Kerberoasting, Golden Ticket,
    Silver Ticket, Pass-the-Ticket, and AS-REP Roasting attacks.
    """
    
    def _get_name(self) -> str:
        return "Kerberos Attack Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'destination_ip', 'service_name', 'ticket_encryption']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze Kerberos traffic for attack patterns.
        
        Detects:
        - Kerberoasting (TGS-REQ for weak encryption types)
        - AS-REP Roasting (pre-auth disabled accounts)
        - Golden/Silver ticket usage (abnormal ticket lifetimes)
        - Pass-the-Ticket (unusual lateral movement patterns)
        - Excessive service ticket requests
        """
        ts_col = col_map.get('timestamp')
        src_col = col_map.get('source_ip')
        dst_col = col_map.get('destination_ip')
        service_col = col_map.get('service_name')
        enc_col = col_map.get('ticket_encryption')
        
        results = []
        
        # Group by source IP
        for source_ip, group in df.groupby(src_col):
            if pd.isna(source_ip):
                continue
            
            request_count = len(group)
            
            # Skip if too few requests
            if request_count < 5:
                continue
            
            score = 0
            flags = []
            
            # Check for Kerberoasting - weak encryption types
            if enc_col and enc_col in group.columns:
                weak_enc_types = ['rc4-hmac', 'rc4', 'des', 'arcfour']  # Order matters for matching
                # Count unique rows with weak encryption (not individual matches)
                weak_enc_count = sum(any(wt in str(val).lower() for wt in weak_enc_types) for val in group[enc_col])
                
                if weak_enc_count > 3:
                    score += 35
                    flags.append('kerberoasting_weak_encryption')
            
            # Check for excessive service ticket requests (potential Kerberoasting)
            if service_col and service_col in group.columns:
                unique_services = group[service_col].nunique()
                
                if unique_services > 20:
                    score += 40
                    flags.append('excessive_tgs_requests')
                elif unique_services > 10:
                    score += 25
                    flags.append('high_tgs_requests')
            
            # Check for AS-REP Roasting patterns (no pre-auth)
            service_names = group[service_col].astype(str).str.lower() if service_col and service_col in group.columns else pd.Series()
            # More specific patterns to avoid false positives
            asrep_count = sum(service_names.str.contains(r'\basrep\b|as-rep|pre-?auth.*disabled', na=False, regex=True))
            
            if asrep_count > 3:
                score += 35
                flags.append('asrep_roasting')
            
            # Check for Golden/Silver ticket indicators
            # Multiple destinations from same source (lateral movement)
            if dst_col and dst_col in group.columns:
                unique_destinations = group[dst_col].nunique()
                
                if unique_destinations > 15:
                    score += 30
                    flags.append('potential_golden_ticket')
                elif unique_destinations > 8:
                    score += 20
                    flags.append('suspicious_lateral_movement')
            
            # Check for rapid ticket requests (automated tools)
            if ts_col and ts_col in df.columns:
                time_span = (group[ts_col].max() - group[ts_col].min()).total_seconds()
                if time_span > 0:
                    requests_per_minute = (request_count / time_span) * 60
                    
                    if requests_per_minute > 30:
                        score += 30
                        flags.append('automated_ticket_requests')
            
            # Check for unusual service names (potential forgery)
            if service_col and service_col in group.columns:
                unusual_services = ['krbtgt', 'fake', 'test', 'admin']
                for svc in group[service_col].astype(str):
                    svc_lower = svc.lower()
                    if any(term in svc_lower for term in unusual_services):
                        score += 25
                        flags.append('suspicious_service_name')
                        break
            
            if score >= 40:  # Only report significant attacks
                results.append({
                    'source_ip': source_ip,
                    'destination_count': group[dst_col].nunique() if dst_col and dst_col in group.columns else 0,
                    'service_count': group[service_col].nunique() if service_col and service_col in group.columns else 0,
                    'request_count': request_count,
                    'first_seen': group[ts_col].min() if ts_col and ts_col in df.columns else None,
                    'last_seen': group[ts_col].max() if ts_col and ts_col in df.columns else None,
                    'flags': ', '.join(set(flags)),
                    'attack_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('attack_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate Kerberos attack visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Bubble chart of attack patterns
        fig = go.Figure(go.Scatter(
            x=result_df['service_count'],
            y=result_df['destination_count'],
            mode='markers',
            marker=dict(
                size=result_df['request_count'] / 10,
                color=result_df['attack_score'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Attack Score"),
                sizemode='diameter',
                sizemin=4
            ),
            text=result_df['source_ip'],
            hovertemplate='<b>%{text}</b><br>Services: %{x}<br>Destinations: %{y}<br>Requests: %{marker.size}<extra></extra>'
        ))
        
        fig.update_layout(
            title='Kerberos Attack Pattern Analysis',
            xaxis_title='Unique Services Requested',
            yaxis_title='Unique Destinations',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for KerberosAttackStrategy output columns."""
        return {
            'source_ip': 'IP address exhibiting Kerberos attack behavior',
            'destination_count': 'Number of unique destinations contacted (lateral movement indicator)',
            'service_count': 'Number of unique services requested (Kerberoasting indicator)',
            'request_count': 'Total number of Kerberos requests',
            'first_seen': 'First timestamp of suspicious activity',
            'last_seen': 'Most recent timestamp of suspicious activity',
            'flags': 'Attack types detected (kerberoasting_weak_encryption, excessive_tgs_requests, asrep_roasting, potential_golden_ticket, automated_ticket_requests, suspicious_service_name)',
            'attack_score': 'Severity score (0-100). Scores ≥75 indicate likely Kerberos attack in progress. Scores ≥50 suggest reconnaissance or preparation'
        }


class MacroMalwareStrategy(HuntStrategy):
    """
    Detects malicious Office macros, VBA execution, embedded scripts,
    and suspicious document behavior patterns.
    """
    
    def _get_name(self) -> str:
        return "Macro Malware Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'filename', 'file_content', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze file and process activity for macro malware.
        
        Detects:
        - Office files with embedded macros
        - VBA execution patterns
        - AutoOpen/AutoExec macros
        - Suspicious process spawning from Office apps
        - Script execution (PowerShell, CMD, WScript)
        """
        ts_col = col_map.get('timestamp')
        file_col = col_map.get('filename')
        content_col = col_map.get('file_content')
        proc_col = col_map.get('process_name')
        
        results = []
        
        # Office applications that can execute macros
        office_apps = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe']
        
        # Suspicious VBA keywords
        vba_suspicious = [
            'autoopen', 'autoexec', 'auto_open', 'workbook_open', 'document_open',
            'shell', 'createobject', 'wscript', 'powershell', 'cmd.exe',
            'downloadfile', 'downloadstring', 'invoke-expression', 'iex',
            'base64', 'frombase64', 'encodedcommand', '-enc', '-e ',
            'bitstransfer', 'webclient', 'net.webclient',
            'regsvr32', 'rundll32', 'mshta', 'certutil'
        ]
        
        for idx, row in df.iterrows():
            filename = row[file_col] if file_col and file_col in row else None
            content = row[content_col] if content_col and content_col in row else None
            process = row[proc_col] if proc_col and proc_col in row else None
            
            if pd.isna(filename) and pd.isna(process):
                continue
            
            score = 0
            flags = []
            
            filename_str = str(filename).lower() if pd.notna(filename) else ''
            content_str = str(content).lower() if pd.notna(content) else ''
            process_str = str(process).lower() if pd.notna(process) else ''
            
            # Check for Office file formats
            # Check for macro-enabled formats
            if any(ext in filename_str for ext in ['.docm', '.xlsm', '.pptm']):
                score += 20
                flags.append('macro_enabled_format')
            
            # Check for VBA content
            if 'vba' in content_str or 'macro' in content_str:
                score += 25
                flags.append('contains_vba_code')
            
            # Check for suspicious VBA keywords
            suspicious_found = [kw for kw in vba_suspicious if kw in content_str]
            if suspicious_found:
                score += 15 * min(len(suspicious_found), 4)  # Cap at 4 keywords
                flags.append('suspicious_vba_keywords')
            
            # Check for AutoOpen/AutoExec
            if any(auto in content_str for auto in ['autoopen', 'autoexec', 'auto_open', 'workbook_open']):
                score += 30
                flags.append('auto_execute_macro')
            
            # Check for process spawning from Office
            parent_is_office = any(app in process_str for app in office_apps)
            
            if parent_is_office:
                # Office spawning suspicious processes
                if any(proc in process_str for proc in ['powershell', 'cmd', 'wscript', 'cscript', 'mshta']):
                    score += 40
                    flags.append('office_spawned_shell')
                
                if any(proc in process_str for proc in ['regsvr32', 'rundll32', 'certutil', 'bitsadmin']):
                    score += 35
                    flags.append('office_spawned_lolbin')
            
            # Check for encoded commands
            if any(enc in content_str for enc in ['base64', 'frombase64', 'encodedcommand', '-enc']):
                score += 30
                flags.append('encoded_command')
            
            # Check for download commands
            if any(dl in content_str for dl in ['downloadfile', 'downloadstring', 'webclient', 'bitstransfer']):
                score += 35
                flags.append('download_capability')
            
            # Check for obfuscation
            OBFUSCATION_CHR_THRESHOLD = 5  # Multiple chr() calls suggest encoding
            OBFUSCATION_CONCAT_THRESHOLD = 20  # Many & concatenations suggest obfuscation
            if content_str.count('chr(') > OBFUSCATION_CHR_THRESHOLD or content_str.count('&') > OBFUSCATION_CONCAT_THRESHOLD:
                score += 25
                flags.append('obfuscated_code')
            
            if score >= 40:  # Only report significant threats
                results.append({
                    'filename': filename if pd.notna(filename) else 'N/A',
                    'process': process if pd.notna(process) else 'N/A',
                    'timestamp': row[ts_col] if ts_col and ts_col in row else None,
                    'flags': ', '.join(set(flags)),
                    'malware_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('malware_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate macro malware visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Bar chart of malware scores
        fig = go.Figure(go.Bar(
            x=result_df['filename'][:20],  # Top 20
            y=result_df['malware_score'][:20],
            marker=dict(
                color=result_df['malware_score'][:20],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Malware Score")
            ),
            text=result_df['malware_score'][:20],
            textposition='outside'
        ))
        
        fig.update_layout(
            title='Top 20 Suspicious Macro Files',
            xaxis_title='Filename',
            yaxis_title='Malware Score',
            height=500,
            xaxis={'tickangle': -45}
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for MacroMalwareStrategy output columns."""
        return {
            'filename': 'Office document filename with suspicious macro behavior',
            'process': 'Process spawned by the Office application',
            'timestamp': 'When the suspicious activity was detected',
            'flags': 'Malware indicators (macro_enabled_format, suspicious_vba_keywords, auto_execute_macro, office_spawned_shell, encoded_command, download_capability, obfuscated_code)',
            'malware_score': 'Severity score (0-100). Scores ≥75 indicate likely malicious macro. Scores ≥50 suggest suspicious document requiring analysis'
        }


class NetworkCovertChannelStrategy(HuntStrategy):
    """
    Detects covert communication channels including ICMP tunneling,
    DNS tunneling, timing channels, and steganography in network protocols.
    """
    
    def _get_name(self) -> str:
        return "Network Covert Channel Detector"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'destination_ip', 'protocol', 'packet_size']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze network traffic for covert channels.
        
        Detects:
        - ICMP tunneling (large/frequent ICMP packets)
        - DNS tunneling (covered by DNSExfiltrationStrategy, but cross-validated)
        - Timing channels (regular intervals suggesting covert timing)
        - Protocol steganography (unusual protocol usage)
        - HTTP header exfiltration
        """
        ts_col = col_map.get('timestamp')
        src_col = col_map.get('source_ip')
        dst_col = col_map.get('destination_ip')
        proto_col = col_map.get('protocol')
        size_col = col_map.get('packet_size')
        
        results = []
        
        # Group by source-destination pairs
        for (source_ip, dest_ip, protocol), group in df.groupby([src_col, dst_col, proto_col]):
            if pd.isna(source_ip) or pd.isna(dest_ip) or pd.isna(protocol):
                continue
            
            packet_count = len(group)
            
            # Need sufficient packets to detect patterns
            if packet_count < 10:
                continue
            
            score = 0
            flags = []
            
            protocol_str = str(protocol).upper()
            
            # Check for ICMP tunneling
            if protocol_str in ['ICMP', 'ICMPV6']:
                # ICMP packets with data payloads
                if size_col and size_col in group.columns:
                    avg_size = group[size_col].mean()
                    
                    # Normal ICMP is small, tunneling uses larger packets
                    if avg_size > 500:
                        score += 40
                        flags.append('icmp_tunneling_large_packets')
                    elif avg_size > 200:
                        score += 25
                        flags.append('icmp_suspicious_size')
                
                # High frequency ICMP is suspicious
                if packet_count > 100:
                    score += 30
                    flags.append('excessive_icmp_traffic')
            
            # Check for timing channel patterns
            if ts_col and ts_col in df.columns:
                timestamps = group[ts_col].sort_values()
                if len(timestamps) > 5:
                    # Calculate inter-packet intervals
                    intervals = timestamps.diff().dt.total_seconds().dropna()
                    
                    if len(intervals) > 5:
                        mean_interval = intervals.mean()
                        std_interval = intervals.std()
                        
                        # Very regular intervals suggest timing channel
                        if mean_interval > 0 and (std_interval / mean_interval) < 0.15:
                            score += 35
                            flags.append('timing_channel_detected')
            
            # Check for unusual protocol usage
            uncommon_protocols = ['GRE', 'IPIP', 'L2TP', 'PPTP']
            if protocol_str in uncommon_protocols:
                score += 25
                flags.append('uncommon_protocol')
            
            # Check for consistent packet sizes (steganography indicator)
            if size_col and size_col in group.columns:
                sizes = group[size_col].dropna()
                if len(sizes) > 10:
                    size_std = sizes.std()
                    size_mean = sizes.mean()
                    
                    # Very consistent sizes suggest covert channel
                    if size_mean > 0 and (size_std / size_mean) < 0.1:
                        score += 30
                        flags.append('consistent_packet_sizes')
            
            # Check for HTTP protocol (potential for anomalies)
            # Note: Without port information, we flag HTTP as potentially suspicious in context
            if protocol_str == 'HTTP' and packet_count > 50:
                score += 15
                flags.append('http_protocol_detected')
            
            # High packet count with small sizes (potential steganography)
            if size_col and size_col in group.columns:
                avg_size = group[size_col].mean()
                if packet_count > 200 and avg_size < 100:
                    score += 25
                    flags.append('micro_packet_stream')
            
            if score >= 40:  # Only report significant covert channels
                results.append({
                    'source_ip': source_ip,
                    'destination_ip': dest_ip,
                    'protocol': protocol,
                    'packet_count': packet_count,
                    'avg_packet_size': group[size_col].mean() if size_col and size_col in group.columns else 0,
                    'first_seen': group[ts_col].min() if ts_col and ts_col in df.columns else None,
                    'last_seen': group[ts_col].max() if ts_col and ts_col in df.columns else None,
                    'flags': ', '.join(set(flags)),
                    'covert_score': min(score, 100)
                })
        
        result_df = pd.DataFrame(results)
        if not result_df.empty:
            result_df = result_df.sort_values('covert_score', ascending=False)
        
        return result_df
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """Generate covert channel visualization."""
        if not HAS_PLOTLY or result_df.empty:
            return None
        
        # Scatter plot by protocol
        fig = go.Figure()
        
        for protocol in result_df['protocol'].unique():
            protocol_data = result_df[result_df['protocol'] == protocol]
            fig.add_trace(go.Scatter(
                x=protocol_data['packet_count'],
                y=protocol_data['covert_score'],
                mode='markers',
                name=protocol,
                marker=dict(size=10),
                text=protocol_data['source_ip'],
                hovertemplate='<b>%{text}</b><br>Protocol: ' + protocol + '<br>Packets: %{x}<br>Score: %{y}<extra></extra>'
            ))
        
        fig.update_layout(
            title='Covert Channel Detection by Protocol',
            xaxis_title='Packet Count',
            yaxis_title='Covert Channel Score',
            height=500
        )
        
        return fig
    
    def get_column_explanations(self) -> dict:
        """Get explanations for NetworkCovertChannelStrategy output columns."""
        return {
            'source_ip': 'Source IP using covert communication channel',
            'destination_ip': 'Destination IP receiving covert communication',
            'protocol': 'Network protocol being abused for covert channel',
            'packet_count': 'Number of packets in the covert stream',
            'avg_packet_size': 'Average packet size in bytes',
            'first_seen': 'First timestamp of covert channel activity',
            'last_seen': 'Most recent timestamp of covert channel activity',
            'flags': 'Covert channel indicators (icmp_tunneling_large_packets, timing_channel_detected, uncommon_protocol, consistent_packet_sizes, micro_packet_stream)',
            'covert_score': 'Severity score (0-100). Scores ≥75 indicate high confidence covert channel. Scores ≥50 suggest suspicious communication patterns'
        }
