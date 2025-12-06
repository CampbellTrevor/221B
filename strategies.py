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
from functools import partial

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
        
        # Filter and sort by beacon score
        if not result_df.empty:
            # Only show high-confidence beacons
            result_df = result_df[result_df['beacon_score'] >= self.MIN_BEACON_SCORE]
            result_df = result_df.sort_values('beacon_score', ascending=False)
        
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
            'beacon_score': 'Overall suspiciousness score (0-100). Higher scores indicate stronger evidence of C2 beaconing. Scores ≥50 suggest automated beaconing behavior worth investigating'
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
        
        # Filter to high-suspicion items only
        result_df = result_df[result_df['suspicion_score'] >= self.MIN_SUSPICION_SCORE]
        
        # Sort by suspicion score (descending)
        result_df = result_df.sort_values('suspicion_score', ascending=False)
        
        # Remove duplicates (aggregate counts if present)
        result_df = result_df.drop_duplicates(subset=['target_string'], keep='first')
        
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
            'suspicion_score': 'Overall suspiciousness score (0-100) combining entropy and length. Higher scores suggest DNS tunneling, Domain Generation Algorithms (DGA), or encoded data. Scores ≥50 warrant investigation'
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
        
        # Filter to high-confidence exfiltration
        result_df = result_df[result_df['exfil_score'] >= self.MIN_EXFIL_SCORE]
        
        # Sort by exfil_score (descending)
        result_df = result_df.sort_values('exfil_score', ascending=False)
        
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
            'exfil_score': 'Overall exfiltration suspiciousness score (0-100) based on ratio, upload volume, and total traffic. Higher scores indicate stronger evidence of data exfiltration. Scores ≥50 suggest potential data theft worth investigating'
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
                flags.append(f"Many connections to few destinations")
            
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
        ts_col = col_map['timestamp']
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
        action_col = col_map['action']
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
            actions = group[action_col].astype(str).tolist()
            statuses = group[status_col].astype(str).tolist()
            
            # Calculate metrics
            total_events = len(group)
            unique_ips = len(set(ips))
            
            # Count failed attempts
            failed_attempts = sum(1 for s in statuses 
                                 if 'fail' in str(s).lower() or 'denied' in str(s).lower() 
                                 or '401' in str(s) or '403' in str(s))
            
            # Count successful events
            success_attempts = sum(1 for s in statuses 
                                  if 'success' in str(s).lower() or 'ok' in str(s).lower() 
                                  or '200' in str(s))
            
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
        has_ua = 'user_agent' in col_map and col_map['user_agent'] in df.columns
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
