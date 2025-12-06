"""
strategies.py - Pure Python analytic logic for 221B threat hunting.

This module contains the abstract base class and concrete implementations
for various threat hunting strategies. No UI or database code is included.
"""

from abc import ABC, abstractmethod
import pandas as pd
import numpy as np
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
        # or numeric codes like 401, 403, etc.
        df['is_failure'] = df[status_col].astype(str).str.lower().str.contains(
            'fail|reject|denied|error|401|403|invalid|wrong', 
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
