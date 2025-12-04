"""
strategies.py - Pure Python analytic logic for 221B threat hunting.

This module contains the abstract base class and concrete implementations
for various threat hunting strategies. No UI or database code is included.
"""

from abc import ABC, abstractmethod
import pandas as pd
import numpy as np
from scipy.stats import entropy

# Try to import plotly for visualizations (optional)
try:
    import plotly.graph_objects as go
    import plotly.express as px
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False


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


class BeaconStrategy(HuntStrategy):
    """
    Beacon Hunter - Detects C2 callbacks by analyzing time patterns.
    
    Calculates variance of time deltas between connections for each
    source/destination pair to identify rhythmic machine-like traffic.
    """
    
    def _get_name(self) -> str:
        return "Beacon Hunter (C2 Detection)"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'dest_ip']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze connection patterns to detect beaconing behavior.
        
        Args:
            df: DataFrame with connection logs
            col_map: Mapping of {'timestamp': actual_col, 'source_ip': actual_col, 
                                  'dest_ip': actual_col}
        
        Returns:
            DataFrame with source_ip, dest_ip, connection_count, delta_variance, and beacon_score
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
            if len(group) < 5:
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
        
        # Filter and sort by beacon score
        if not result_df.empty:
            # Only show high-confidence beacons (score >= 50)
            result_df = result_df[result_df['beacon_score'] >= 50]
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
            text=[f"Source: {row['source_ip']}<br>Dest: {row['dest_ip']}<br>Score: {row['beacon_score']:.0f}<br>Connections: {row['connection_count']}" 
                  for _, row in result_df.iterrows()],
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


class EntropyStrategy(HuntStrategy):
    """
    Entropy Analyzer - Detects DNS tunneling and DGA domains.
    
    Calculates Shannon Entropy on string fields to identify
    high-entropy, long strings indicative of data exfiltration.
    """
    
    def _get_name(self) -> str:
        return "Entropy Analyzer (DNS Tunneling)"
    
    def _get_required_inputs(self) -> list:
        return ['target_string']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Calculate Shannon Entropy for string fields.
        
        Args:
            df: DataFrame with string data (e.g., DNS queries)
            col_map: Mapping of {'target_string': actual_col}
        
        Returns:
            DataFrame with target_string, string_length, entropy_score, and suspicion_score
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
        
        # Filter to high-suspicion items only (score >= 50)
        result_df = result_df[result_df['suspicion_score'] >= 50]
        
        # Sort by suspicion score (descending)
        result_df = result_df.sort_values('suspicion_score', ascending=False)
        
        # Remove duplicates (aggregate counts if present)
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
            text=[f"String: {row['target_string'][:50]}{'...' if len(row['target_string']) > 50 else ''}<br>Length: {row['string_length']}<br>Entropy: {row['entropy_score']:.2f}<br>Score: {row['suspicion_score']:.0f}" 
                  for _, row in result_df.iterrows()],
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


class ExfilStrategy(HuntStrategy):
    """
    Exfiltration Monitor - Detects data exfiltration by traffic ratio.
    
    Calculates the ratio of bytes_out/bytes_in to identify hosts
    behaving as "producers" rather than "consumers".
    """
    
    # Constant for pure upload cases (bytes_in = 0, bytes_out > 0)
    PURE_UPLOAD_RATIO = 999999.0
    
    def _get_name(self) -> str:
        return "Exfiltration Monitor (Producer/Consumer Ratio)"
    
    def _get_required_inputs(self) -> list:
        return ['source_ip', 'bytes_out', 'bytes_in']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Calculate upload/download ratio for each source IP.
        
        Args:
            df: DataFrame with connection logs
            col_map: Mapping of {'source_ip': actual_col, 'bytes_out': actual_col,
                                  'bytes_in': actual_col}
        
        Returns:
            DataFrame with source_ip, total_bytes_out, total_bytes_in, exfil_ratio
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
        min_bytes_threshold = 1000  # At least 1KB of traffic
        result_df = result_df[
            (result_df['total_bytes_out'] + result_df['total_bytes_in']) >= min_bytes_threshold
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
        
        # Filter to high-confidence exfiltration (score >= 50)
        result_df = result_df[result_df['exfil_score'] >= 50]
        
        # Sort by exfil_score (descending)
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
            text=[f"Source: {row['source_ip']}<br>Upload: {row['bytes_out_mb']:.2f} MB<br>Download: {row['bytes_in_mb']:.2f} MB<br>Ratio: {row['exfil_ratio']:.2f}<br>Score: {row['exfil_score']:.0f}" 
                  for _, row in result_df.iterrows()],
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
