"""
strategies.py - Pure Python analytic logic for 221B threat hunting.

This module contains the abstract base class and concrete implementations
for various threat hunting strategies. No UI or database code is included.
"""

from abc import ABC, abstractmethod
import pandas as pd
import numpy as np
from scipy.stats import entropy


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
            DataFrame with source_ip, dest_ip, connection_count, delta_variance
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
            if len(group) < 2:
                continue
            
            # Calculate time deltas in seconds
            timestamps = group[ts_col].values
            deltas = np.diff(timestamps).astype('timedelta64[s]').astype(float)
            
            if len(deltas) > 0:
                variance = np.var(deltas)
                results.append({
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'connection_count': len(group),
                    'delta_variance': variance,
                    'mean_delta': np.mean(deltas)
                })
        
        result_df = pd.DataFrame(results)
        
        # Sort by variance (lower variance = more rhythmic = more suspicious)
        if not result_df.empty:
            result_df = result_df.sort_values('delta_variance')
        
        return result_df


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
            DataFrame with target_string, string_length, entropy_score
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
        
        # Create result DataFrame
        result_df = df[[str_col, 'string_length', 'entropy_score']].copy()
        result_df = result_df.rename(columns={str_col: 'target_string'})
        
        # Sort by entropy score (descending)
        result_df = result_df.sort_values('entropy_score', ascending=False)
        
        return result_df


class ExfilStrategy(HuntStrategy):
    """
    Exfiltration Monitor - Detects data exfiltration by traffic ratio.
    
    Calculates the ratio of bytes_out/bytes_in to identify hosts
    behaving as "producers" rather than "consumers".
    """
    
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
        
        # Filter out rows with no traffic (both in and out are zero)
        result_df = result_df[
            (result_df['total_bytes_out'] > 0) | (result_df['total_bytes_in'] > 0)
        ]
        
        # Calculate ratio with better handling of edge cases
        # Use vectorized operations for better performance
        result_df['exfil_ratio'] = np.where(
            result_df['total_bytes_in'] > 0,
            result_df['total_bytes_out'] / result_df['total_bytes_in'],
            # If bytes_in is 0 but bytes_out > 0, use a large but not infinite value
            np.where(
                result_df['total_bytes_out'] > 0,
                999999.0,  # Large value indicating pure upload
                0.0  # Both are zero (already filtered above, but for safety)
            )
        )
        
        # Add total traffic for additional context
        result_df['total_bytes'] = result_df['total_bytes_out'] + result_df['total_bytes_in']
        
        # Sort by exfil_ratio (descending), then by total_bytes_out
        result_df = result_df.sort_values(['exfil_ratio', 'total_bytes_out'], ascending=[False, False])
        
        return result_df
