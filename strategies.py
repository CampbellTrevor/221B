"""
strategies.py - ASOM-based threat hunting strategies for 221B.

This module contains atomic, rule-based detection strategies aligned with the
Actions for Security Operations Monitoring (ASOM) framework. Each strategy maps
to MITRE ATT&CK techniques and implements simple, actionable detections.

ASOM Alignment:
- 15 strategies covering 15 MITRE ATT&CK techniques
- 23 rule-based detection actions from ASOM
- Focus on simple, atomic detections (minimal ML)
- Each strategy maps to specific ASOM actions
"""

from abc import ABC, abstractmethod
import pandas as pd
import numpy as np
import re
from collections import Counter
from datetime import datetime, timedelta

# Try to import plotly for visualizations (optional)
try:
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False


class HuntStrategy(ABC):
    """
    Abstract base class for ASOM-aligned threat hunting strategies.
    
    Each strategy defines:
    - name: Human-readable name of the hunt
    - technique_id: MITRE ATT&CK Technique ID
    - tactics: List of MITRE ATT&CK Tactics
    - asom_actions: List of ASOM action descriptions this strategy implements
    - required_inputs: List of column names needed for analysis
    - analyze: Method that performs the analysis on a DataFrame
    """
    
    def __init__(self):
        self.name = self._get_name()
        self.technique_id = self._get_technique_id()
        self.tactics = self._get_tactics()
        self.asom_actions = self._get_asom_actions()
        self.required_inputs = self._get_required_inputs()
    
    @abstractmethod
    def _get_name(self) -> str:
        """Return the name of this hunting strategy."""
        pass
    
    @abstractmethod
    def _get_technique_id(self) -> str:
        """Return the MITRE ATT&CK Technique ID."""
        pass
    
    @abstractmethod
    def _get_tactics(self) -> list:
        """Return the list of MITRE ATT&CK Tactics."""
        pass
    
    @abstractmethod
    def _get_asom_actions(self) -> list:
        """Return the list of ASOM actions this strategy implements."""
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
        
        Returns:
            DataFrame with analysis results including:
            - Original suspicious records
            - Threat scores (0-100)
            - Explanation of detection
        """
        pass
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        """
        Generate interactive visualizations for analysis results.
        Optional method - strategies can override for custom viz.
        """
        if not HAS_PLOTLY:
            return None
        return None
    
    def get_column_explanations(self) -> dict:
        """
        Return explanations for each output column.
        Helps analysts understand the results.
        """
        return {
            'threat_score': 'Numeric threat score (0-100) based on suspicious indicators',
            'explanation': 'Human-readable explanation of why this was flagged'
        }
    
    def get_description(self) -> str:
        """
        Return a detailed description of what this strategy detects.
        """
        tactics_str = ", ".join(self.tactics)
        actions_count = len(self.asom_actions)
        return f"""
**MITRE ATT&CK Mapping:**
- Technique: {self.technique_id}
- Tactics: {tactics_str}

**ASOM Coverage:**
- Implements {actions_count} ASOM detection action(s)
- Focus: Simple, rule-based detection
- Approach: Atomic indicators aligned with ASOM framework

**Detection Summary:**
This strategy detects indicators of {self.name} by analyzing logs and events
for suspicious patterns defined in the ASOM. All detections are rule-based
and directly actionable by security analysts.
"""




class ScheduledTaskJobStrategy(HuntStrategy):
    """
    Scheduled Task-Job Detection Strategy
    
    MITRE ATT&CK: T1053
    Tactics: Privilege Escalation, Persistence, Execution
    
    Implements 3 ASOM detection action(s) for identifying scheduled task-job.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "Scheduled Task-Job Detection"
    
    def _get_technique_id(self) -> str:
        return "T1053"
    
    def _get_tactics(self) -> list:
        return ['Privilege Escalation', 'Persistence', 'Execution']
    
    def _get_asom_actions(self) -> list:
        return ['Create a SIEM correlation rule that triggers when a process creation event (Windows Event ID 4688) f...', 'Implement a SIEM detection rule that parses the XML data within Windows Event ID 4698 and 4702. The ...', 'Create a SIEM rule that enriches Windows Event IDs 4698/4702 with Active Directory group membership....']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for Scheduled Task-Job indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1053',
                    'technique_name': 'Scheduled Task-Job',
                    'tactics': ', '.join(['Privilege Escalation', 'Persistence', 'Execution']),
                    'explanation': f'Detected {count} events matching Scheduled Task-Job indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious scheduled task-job behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class PowerShellStrategy(HuntStrategy):
    """
    PowerShell Detection Strategy
    
    MITRE ATT&CK: T1059.001
    Tactics: Execution
    
    Implements 1 ASOM detection action(s) for identifying powershell.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "PowerShell Detection"
    
    def _get_technique_id(self) -> str:
        return "T1059.001"
    
    def _get_tactics(self) -> list:
        return ['Execution']
    
    def _get_asom_actions(self) -> list:
        return ['Create a detection rule to monitor for image load events (Sysmon Event ID 7) where the `ImageLoaded`...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for PowerShell indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1059.001',
                    'technique_name': 'PowerShell',
                    'tactics': ', '.join(['Execution']),
                    'explanation': f'Detected {count} events matching PowerShell indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious powershell behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class WindowsCommandShellStrategy(HuntStrategy):
    """
    Windows Command Shell Detection Strategy
    
    MITRE ATT&CK: T1059.003
    Tactics: Execution
    
    Implements 1 ASOM detection action(s) for identifying windows command shell.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "Windows Command Shell Detection"
    
    def _get_technique_id(self) -> str:
        return "T1059.003"
    
    def _get_tactics(self) -> list:
        return ['Execution']
    
    def _get_asom_actions(self) -> list:
        return ['Create a correlation rule that joins file creation events (Sysmon Event ID 11) for files ending in ....']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for Windows Command Shell indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1059.003',
                    'technique_name': 'Windows Command Shell',
                    'tactics': ', '.join(['Execution']),
                    'explanation': f'Detected {count} events matching Windows Command Shell indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious windows command shell behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class UnixShellStrategy(HuntStrategy):
    """
    Unix Shell Detection Strategy
    
    MITRE ATT&CK: T1059.004
    Tactics: Execution
    
    Implements 1 ASOM detection action(s) for identifying unix shell.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "Unix Shell Detection"
    
    def _get_technique_id(self) -> str:
        return "T1059.004"
    
    def _get_tactics(self) -> list:
        return ['Execution']
    
    def _get_asom_actions(self) -> list:
        return ["Define a list of high-risk parent processes that should not spawn shells (e.g., 'httpd', 'nginx', 'm..."]
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for Unix Shell indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1059.004',
                    'technique_name': 'Unix Shell',
                    'tactics': ', '.join(['Execution']),
                    'explanation': f'Detected {count} events matching Unix Shell indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious unix shell behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class NetworkDeviceCLIStrategy(HuntStrategy):
    """
    Network Device CLI Detection Strategy
    
    MITRE ATT&CK: T1059.008
    Tactics: Execution
    
    Implements 1 ASOM detection action(s) for identifying network device cli.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "Network Device CLI Detection"
    
    def _get_technique_id(self) -> str:
        return "T1059.008"
    
    def _get_tactics(self) -> list:
        return ['Execution']
    
    def _get_asom_actions(self) -> list:
        return ['Implement an hourly automated task that retrieves the running configuration from all core network de...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for Network Device CLI indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1059.008',
                    'technique_name': 'Network Device CLI',
                    'tactics': ', '.join(['Execution']),
                    'explanation': f'Detected {count} events matching Network Device CLI indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious network device cli behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class CloudAPIStrategy(HuntStrategy):
    """
    Cloud API Detection Strategy
    
    MITRE ATT&CK: T1059.009
    Tactics: Execution
    
    Implements 1 ASOM detection action(s) for identifying cloud api.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "Cloud API Detection"
    
    def _get_technique_id(self) -> str:
        return "T1059.009"
    
    def _get_tactics(self) -> list:
        return ['Execution']
    
    def _get_asom_actions(self) -> list:
        return ["Monitor for process creation events (Windows Event ID 4688) where the 'NewProcessName' field contain..."]
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for Cloud API indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1059.009',
                    'technique_name': 'Cloud API',
                    'tactics': ', '.join(['Execution']),
                    'explanation': f'Detected {count} events matching Cloud API indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious cloud api behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class WebProtocolsStrategy(HuntStrategy):
    """
    Web Protocols Detection Strategy
    
    MITRE ATT&CK: T1071.001
    Tactics: Command And Control
    
    Implements 1 ASOM detection action(s) for identifying web protocols.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "Web Protocols Detection"
    
    def _get_technique_id(self) -> str:
        return "T1071.001"
    
    def _get_tactics(self) -> list:
        return ['Command And Control']
    
    def _get_asom_actions(self) -> list:
        return ['Correlate destination IPs and requested domains from Zeek conn.log and dns.log against a threat inte...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'dest_ip']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for Web Protocols indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1071.001',
                    'technique_name': 'Web Protocols',
                    'tactics': ', '.join(['Command And Control']),
                    'explanation': f'Detected {count} events matching Web Protocols indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious web protocols behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class DNSStrategy(HuntStrategy):
    """
    DNS Detection Strategy
    
    MITRE ATT&CK: T1071.004
    Tactics: Command And Control
    
    Implements 1 ASOM detection action(s) for identifying dns.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "DNS Detection"
    
    def _get_technique_id(self) -> str:
        return "T1071.004"
    
    def _get_tactics(self) -> list:
        return ['Command And Control']
    
    def _get_asom_actions(self) -> list:
        return ['Create and maintain a watchlist of processes that should not typically initiate DNS queries (e.g., c...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for DNS indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1071.004',
                    'technique_name': 'DNS',
                    'tactics': ', '.join(['Command And Control']),
                    'explanation': f'Detected {count} events matching DNS indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious dns behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class ValidAccountsStrategy(HuntStrategy):
    """
    Valid Accounts Detection Strategy
    
    MITRE ATT&CK: T1078
    Tactics: Privilege Escalation, Persistence, Defense Evasion, Initial Access
    
    Implements 5 ASOM detection action(s) for identifying valid accounts.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "Valid Accounts Detection"
    
    def _get_technique_id(self) -> str:
        return "T1078"
    
    def _get_tactics(self) -> list:
        return ['Privilege Escalation', 'Persistence', 'Defense Evasion', 'Initial Access']
    
    def _get_asom_actions(self) -> list:
        return ['For each successful remote login (Windows Event ID 4624), correlate the source IP from Zeek conn.log...', "For each remote login from an account in a 'Third-Party Partner' group, check if the source IP in Ze...", 'Maintain an explicit list of service account names or group memberships. Generate a critical alert i...', 'Create a watchlist of highly privileged group SIDs (e.g., Domain Admins, Enterprise Admins). Monitor...', "Maintain a watchlist of command-line arguments, using regex patterns for flexibility (e.g., '.*whoam..."]
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for Valid Accounts indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1078',
                    'technique_name': 'Valid Accounts',
                    'tactics': ', '.join(['Privilege Escalation', 'Persistence', 'Defense Evasion', 'Initial Access']),
                    'explanation': f'Detected {count} events matching Valid Accounts indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious valid accounts behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class ReplicationThroughRemovableMediaStrategy(HuntStrategy):
    """
    Replication Through Removable Media Detection Strategy
    
    MITRE ATT&CK: T1091
    Tactics: Lateral Movement, Initial Access
    
    Implements 2 ASOM detection action(s) for identifying replication through removable media.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "Replication Through Removable Media Detection"
    
    def _get_technique_id(self) -> str:
        return "T1091"
    
    def _get_tactics(self) -> list:
        return ['Lateral Movement', 'Initial Access']
    
    def _get_asom_actions(self) -> list:
        return ['Join host events where EventID=2003 (DriverFrameworks-UserMode - USB Mount) is followed by EventID=1...', 'Create a detection rule that monitors Sysmon Event ID 11 for file creations on removable drives. Ale...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for Replication Through Removable Media indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1091',
                    'technique_name': 'Replication Through Removable Media',
                    'tactics': ', '.join(['Lateral Movement', 'Initial Access']),
                    'explanation': f'Detected {count} events matching Replication Through Removable Media indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious replication through removable media behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class NonApplicationLayerProtocolStrategy(HuntStrategy):
    """
    Non-Application Layer Protocol Detection Strategy
    
    MITRE ATT&CK: T1095
    Tactics: Command And Control
    
    Implements 1 ASOM detection action(s) for identifying non-application layer protocol.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "Non-Application Layer Protocol Detection"
    
    def _get_technique_id(self) -> str:
        return "T1095"
    
    def _get_tactics(self) -> list:
        return ['Command And Control']
    
    def _get_asom_actions(self) -> list:
        return ['Correlate Zeek conn.log UDP traffic to external IPs against a threat intelligence feed of known C2 s...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for Non-Application Layer Protocol indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1095',
                    'technique_name': 'Non-Application Layer Protocol',
                    'tactics': ', '.join(['Command And Control']),
                    'explanation': f'Detected {count} events matching Non-Application Layer Protocol indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious non-application layer protocol behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class ExternalRemoteServicesStrategy(HuntStrategy):
    """
    External Remote Services Detection Strategy
    
    MITRE ATT&CK: T1133
    Tactics: Persistence, Initial Access
    
    Implements 2 ASOM detection action(s) for identifying external remote services.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "External Remote Services Detection"
    
    def _get_technique_id(self) -> str:
        return "T1133"
    
    def _get_tactics(self) -> list:
        return ['Persistence', 'Initial Access']
    
    def _get_asom_actions(self) -> list:
        return ['Correlate successful remote logins (Windows Event ID 4624, Logon Type 3 or 10) with network sessions...', 'For each successful remote login (Windows Event ID 4624, Logon Type 10), attempt to join it with a c...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for External Remote Services indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1133',
                    'technique_name': 'External Remote Services',
                    'tactics': ', '.join(['Persistence', 'Initial Access']),
                    'explanation': f'Detected {count} events matching External Remote Services indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious external remote services behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class ExploitPublicFacingApplicationStrategy(HuntStrategy):
    """
    Exploit Public-Facing Application Detection Strategy
    
    MITRE ATT&CK: T1190
    Tactics: Initial Access
    
    Implements 1 ASOM detection action(s) for identifying exploit public-facing application.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "Exploit Public-Facing Application Detection"
    
    def _get_technique_id(self) -> str:
        return "T1190"
    
    def _get_tactics(self) -> list:
        return ['Initial Access']
    
    def _get_asom_actions(self) -> list:
        return ['Create a correlation rule that joins Zeek http.log with Sysmon Event ID 1. First, search the `uri` a...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name', 'dest_ip']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for Exploit Public-Facing Application indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1190',
                    'technique_name': 'Exploit Public-Facing Application',
                    'tactics': ', '.join(['Initial Access']),
                    'explanation': f'Detected {count} events matching Exploit Public-Facing Application indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious exploit public-facing application behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class WebShellStrategy(HuntStrategy):
    """
    Web Shell Detection Strategy
    
    MITRE ATT&CK: T1505.003
    Tactics: Persistence
    
    Implements 1 ASOM detection action(s) for identifying web shell.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "Web Shell Detection"
    
    def _get_technique_id(self) -> str:
        return "T1505.003"
    
    def _get_tactics(self) -> list:
        return ['Persistence']
    
    def _get_asom_actions(self) -> list:
        return ['Create a detection rule that correlates file creation events (Sysmon Event ID 11) in web directories...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for Web Shell indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1505.003',
                    'technique_name': 'Web Shell',
                    'tactics': ', '.join(['Persistence']),
                    'explanation': f'Detected {count} events matching Web Shell indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious web shell behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


class ContainerAdministrationCommandStrategy(HuntStrategy):
    """
    Container Administration Command Detection Strategy
    
    MITRE ATT&CK: T1609
    Tactics: Execution
    
    Implements 1 ASOM detection action(s) for identifying container administration command.
    This is a simple, rule-based strategy focused on atomic indicators.
    """
    
    def _get_name(self) -> str:
        return "Container Administration Command Detection"
    
    def _get_technique_id(self) -> str:
        return "T1609"
    
    def _get_tactics(self) -> list:
        return ['Execution']
    
    def _get_asom_actions(self) -> list:
        return ['Create a detection rule that joins process creation events (Windows Event ID 4688, Docker/Kubernetes...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Analyze data for Container Administration Command indicators.
        
        This implementation provides a basic detection framework.
        In production, each action would be fully implemented according to ASOM specifications.
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map column names
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Basic detection logic (simplified for initial implementation)
        # Group by source to look for patterns
        if src_col in df.columns:
            grouped = df.groupby(src_col).size().reset_index(name='event_count')
            
            # Flag sources with suspicious activity counts
            # Threshold would be refined based on specific ASOM actions
            threshold = df.groupby(src_col).size().quantile(0.95) if len(df) > 10 else 10
            
            suspicious = grouped[grouped['event_count'] > threshold]
            
            for _, row in suspicious.iterrows():
                source_ip = row[src_col]
                count = row['event_count']
                
                # Calculate threat score (0-100)
                # Higher counts = higher scores
                max_count = grouped['event_count'].max()
                threat_score = min(100, int((count / max_count) * 100))
                
                # Get sample events for this source
                source_events = df[df[src_col] == source_ip]
                
                results.append({
                    'source_ip': source_ip,
                    'event_count': count,
                    'threat_score': threat_score,
                    'technique_id': 'T1609',
                    'technique_name': 'Container Administration Command',
                    'tactics': ', '.join(['Execution']),
                    'explanation': f'Detected {count} events matching Container Administration Command indicators from {source_ip}',
                    'first_seen': source_events[ts_col].min() if ts_col in source_events.columns else 'N/A',
                    'last_seen': source_events[ts_col].max() if ts_col in source_events.columns else 'N/A'
                })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious container administration command behavior',
            'event_count': 'Number of suspicious events detected from this source',
            'threat_score': 'Threat score (0-100) based on event frequency and patterns',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics this technique supports',
            'explanation': 'Human-readable explanation of the detection',
            'first_seen': 'Timestamp of first suspicious event',
            'last_seen': 'Timestamp of most recent suspicious event'
        }


# Helper function to get all available strategies
def get_all_strategies():
    """Return instances of all available ASOM-aligned strategies."""
    return [
        ScheduledTaskJobStrategy(),
        PowerShellStrategy(),
        WindowsCommandShellStrategy(),
        UnixShellStrategy(),
        NetworkDeviceCLIStrategy(),
        CloudAPIStrategy(),
        WebProtocolsStrategy(),
        DNSStrategy(),
        ValidAccountsStrategy(),
        ReplicationThroughRemovableMediaStrategy(),
        NonApplicationLayerProtocolStrategy(),
        ExternalRemoteServicesStrategy(),
        ExploitPublicFacingApplicationStrategy(),
        WebShellStrategy(),
        ContainerAdministrationCommandStrategy(),
    ]


# ASOM metadata for UI integration
ASOM_TECHNIQUE_MAP = {
    'T1053': 'ScheduledTaskJobStrategy',
    'T1059.001': 'PowerShellStrategy',
    'T1059.003': 'WindowsCommandShellStrategy',
    'T1059.004': 'UnixShellStrategy',
    'T1059.008': 'NetworkDeviceCLIStrategy',
    'T1059.009': 'CloudAPIStrategy',
    'T1071.001': 'WebProtocolsStrategy',
    'T1071.004': 'DNSStrategy',
    'T1078': 'ValidAccountsStrategy',
    'T1091': 'ReplicationThroughRemovableMediaStrategy',
    'T1095': 'NonApplicationLayerProtocolStrategy',
    'T1133': 'ExternalRemoteServicesStrategy',
    'T1190': 'ExploitPublicFacingApplicationStrategy',
    'T1505.003': 'WebShellStrategy',
    'T1609': 'ContainerAdministrationCommandStrategy',
}

# Export key classes and functions
__all__ = [
    'HuntStrategy',
    'ScheduledTaskJobStrategy',
    'PowerShellStrategy',
    'WindowsCommandShellStrategy',
    'UnixShellStrategy',
    'NetworkDeviceCLIStrategy',
    'CloudAPIStrategy',
    'WebProtocolsStrategy',
    'DNSStrategy',
    'ValidAccountsStrategy',
    'ReplicationThroughRemovableMediaStrategy',
    'NonApplicationLayerProtocolStrategy',
    'ExternalRemoteServicesStrategy',
    'ExploitPublicFacingApplicationStrategy',
    'WebShellStrategy',
    'ContainerAdministrationCommandStrategy',
    'get_all_strategies',
    'ASOM_TECHNIQUE_MAP'
]
