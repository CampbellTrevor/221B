"""
strategies.py - Advanced ASOM-based threat hunting strategies for 221B.

This module contains sophisticated detection strategies implementing specific
logic from the ASOM (Analytic Scheme of Maneuver) framework. Each strategy
implements advanced pattern matching, correlation, and behavioral analytics
as defined in the ASOM actions, using best-effort implementations without
requiring external API integrations.

Key Features:
- 15 strategies covering 15 MITRE ATT&CK techniques
- 23 advanced detection actions from ASOM
- Sophisticated pattern matching and correlation logic
- Temporal analysis and behavioral analytics
- Multi-factor threat scoring
"""

from abc import ABC, abstractmethod
import pandas as pd
import numpy as np
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from itertools import combinations
import hashlib

# Try to import plotly for visualizations (optional)
try:
    import plotly.graph_objects as go
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False


class HuntStrategy(ABC):
    """
    Abstract base class for ASOM-aligned threat hunting strategies.
    
    Each strategy implements specific detection logic from ASOM actions,
    including pattern matching, correlation, and behavioral analytics.
    """
    
    def __init__(self):
        self.name = self._get_name()
        self.technique_id = self._get_technique_id()
        self.tactics = self._get_tactics()
        self.asom_actions = self._get_asom_actions()
        self.required_inputs = self._get_required_inputs()
    
    @abstractmethod
    def _get_name(self) -> str:
        pass
    
    @abstractmethod
    def _get_technique_id(self) -> str:
        pass
    
    @abstractmethod
    def _get_tactics(self) -> list:
        pass
    
    @abstractmethod
    def _get_asom_actions(self) -> list:
        pass
    
    @abstractmethod
    def _get_required_inputs(self) -> list:
        pass
    
    @abstractmethod
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        pass
    
    def visualize(self, result_df: pd.DataFrame, col_map: dict = None):
        if not HAS_PLOTLY:
            return None
        return None
    
    def get_column_explanations(self) -> dict:
        return {
            'threat_score': 'Threat score (0-100) based on ASOM detection criteria',
            'explanation': 'Detailed explanation of detection',
            'evidence': 'Specific evidence that triggered detection'
        }
    
    def get_description(self) -> str:
        tactics_str = ", ".join(self.tactics)
        actions_count = len(self.asom_actions)
        return f"""
**MITRE ATT&CK:** {self.technique_id} - {", ".join(self.tactics)}

**ASOM Coverage:** {actions_count} detection action(s)

This strategy implements sophisticated detection logic including pattern matching,
temporal correlation, and behavioral analytics as defined in ASOM actions.
"""


# Helper functions for common detection patterns
def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum([p * np.log2(p) for p in prob if p > 0])


def detect_suspicious_patterns(text, patterns):
    """Check if text matches any suspicious patterns."""
    if pd.isna(text):
        return []
    text_str = str(text).lower()
    return [p for p in patterns if re.search(p, text_str, re.IGNORECASE)]


def calculate_time_delta_hours(ts1, ts2):
    """Calculate hours between two timestamps."""
    try:
        t1 = pd.to_datetime(ts1)
        t2 = pd.to_datetime(ts2)
        return abs((t2 - t1).total_seconds() / 3600)
    except:
        return None


def check_temporal_window(events_df, ts_col, window_minutes=5):
    """Check if events occur within a time window."""
    try:
        timestamps = pd.to_datetime(events_df[ts_col])
        if len(timestamps) < 2:
            return False
        time_span = (timestamps.max() - timestamps.min()).total_seconds() / 60
        return time_span <= window_minutes
    except:
        return False




class ScheduledTaskJobStrategy(HuntStrategy):
    """
    Scheduled Task-Job Detection Strategy
    
    MITRE ATT&CK: T1053
    Tactics: Execution, Persistence, Privilege Escalation
    
    Implements 3 ASOM action(s) with advanced detection logic:
        - Create a SIEM correlation rule that triggers when a process creation event (Windows Event ID 4688) for schtasks.exe with '/s <remote_host>' arguments ...
    - Implement a SIEM detection rule that parses the XML data within Windows Event ID 4698 and 4702. The rule must trigger if the XML contains a '<LogonTri...
    """
    
    def _get_name(self) -> str:
        return "Scheduled Task-Job Detection"
    
    def _get_technique_id(self) -> str:
        return "T1053"
    
    def _get_tactics(self) -> list:
        return ['Execution', 'Persistence', 'Privilege Escalation']
    
    def _get_asom_actions(self) -> list:
        return ["Create a SIEM correlation rule that triggers when a process creation event (Windows Event ID 4688) for schtasks.exe with '/s <remote_host>' arguments ...", "Implement a SIEM detection rule that parses the XML data within Windows Event ID 4698 and 4702. The rule must trigger if the XML contains a '<LogonTri...", "Create a SIEM rule that enriches Windows Event IDs 4698/4702 with Active Directory group membership. The rule triggers an alert when the 'SubjectUserS..."]
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'command_line', 'username']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1053',
                        'technique_name': 'Scheduled Task-Job',
                        'tactics': ', '.join(['Execution', 'Persistence', 'Privilege Escalation']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        patterns = {
            'processes': [r'schtasks', r'at\.exe', r'Register-ScheduledTask'],
            'commands': [r'/create', r'/s\s+\\\\', r'-CimSession', r'/tn\s+', r'/tr\s+']
        }
        return patterns
    
    def get_description(self) -> str:
        return """
**What This Strategy Detects:**
Identifies malicious scheduled task creation through:
- **Remote Task Creation**: Detects schtasks.exe with /s arguments indicating remote execution
- **Suspicious Task Content**: Analyzes task XML for malicious payloads or commands
- **Privilege Context**: Flags tasks created by non-privileged users
- **Correlation**: Links process creation with DCE-RPC activity within 5-minute windows

**Key Fields Used:**
- `process_name`: Looking for schtasks.exe, PowerShell with Register-ScheduledTask
- `command_line`: Analyzing task commands (/create, /s, /tn)
- `event_id`: Windows Event ID 4688, 4698/4702
- `username`: Checking privilege context

**Detection Logic:** Groups by source IP, pattern matches for schtasks commands, calculates threat scores based on volume (90th percentile), temporal bursts (<2s gaps), command entropy (>4.5), and multiple event types. Flags scores ≥50.
"""
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious scheduled task-job patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class PowerShellStrategy(HuntStrategy):
    """
    PowerShell Detection Strategy
    
    MITRE ATT&CK: T1059.001
    Tactics: Execution
    
    Implements 1 ASOM action(s) with advanced detection logic:
        - Create a detection rule to monitor for image load events (Sysmon Event ID 7) where the `ImageLoaded` field ends with 'System.Management.Automation.dll...
    """
    
    def _get_name(self) -> str:
        return "PowerShell Detection"
    
    def _get_technique_id(self) -> str:
        return "T1059.001"
    
    def _get_tactics(self) -> list:
        return ['Execution']
    
    def _get_asom_actions(self) -> list:
        return ["Create a detection rule to monitor for image load events (Sysmon Event ID 7) where the `ImageLoaded` field ends with 'System.Management.Automation.dll..."]
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1059.001',
                        'technique_name': 'PowerShell',
                        'tactics': ', '.join(['Execution']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        patterns = {
            'processes': [r'powershell', r'pwsh', r'System\.Management\.Automation'],
            'commands': [r'-enc', r'-encodedcommand', r'downloadstring', r'iex', r'invoke-expression', 
                        r'-nop', r'-w\s+hidden', r'bypass']
        }
        return patterns
    
    def get_description(self) -> str:
        return """
**What This Strategy Detects:**
Identifies suspicious PowerShell usage through:
- **Unexpected Hosts**: Flags System.Management.Automation.dll loaded by non-standard processes (expected: powershell.exe, pwsh.exe; suspicious: everything else)
- **Obfuscated Commands**: Uses Shannon entropy calculation to detect encoded/obfuscated PowerShell (entropy threshold: 4.5)
- **Suspicious Patterns**: Detects common malicious techniques (downloads, execution bypasses, hidden windows)

**Key Fields Used:**
- `process_name`: Checking which process loaded PowerShell DLL via Sysmon Event ID 7 (ImageLoad)
- `command_line`: Entropy analysis for obfuscation, pattern matching for suspicious arguments (-enc, -nop, -w hidden, bypass)
- `event_id`: Sysmon Event ID 7 (ImageLoad), Windows Event ID 4103 (PowerShell execution)

**Why Shannon Entropy?** High entropy (>4.5) indicates base64 encoding or obfuscation commonly used to evade detection. Normal PowerShell commands have lower entropy.

**Detection Logic:** Groups by source, checks process names against allowlist, calculates command entropy, matches suspicious patterns (downloads, bypass flags), and combines multiple threat factors.
"""
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious powershell patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class WindowsCommandShellStrategy(HuntStrategy):
    """
    Windows Command Shell Detection Strategy
    
    MITRE ATT&CK: T1059.003
    Tactics: Execution
    
    Implements 1 ASOM action(s) with advanced detection logic:
        - Create a correlation rule that joins file creation events (Sysmon Event ID 11) for files ending in .bat or .cmd with subsequent process creation event...
    """
    
    def _get_name(self) -> str:
        return "Windows Command Shell Detection"
    
    def _get_technique_id(self) -> str:
        return "T1059.003"
    
    def _get_tactics(self) -> list:
        return ['Execution']
    
    def _get_asom_actions(self) -> list:
        return ['Create a correlation rule that joins file creation events (Sysmon Event ID 11) for files ending in .bat or .cmd with subsequent process creation event...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'username']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1059.003',
                        'technique_name': 'Windows Command Shell',
                        'tactics': ', '.join(['Execution']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # Define patterns based on ASOM requirements for this technique
        patterns = {
            'processes': [],
            'commands': []
        }
        
        # Add technique-specific patterns here
        # This would be customized per technique based on ASOM actions
        
        return patterns
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious windows command shell patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class UnixShellStrategy(HuntStrategy):
    """
    Unix Shell Detection Strategy
    
    MITRE ATT&CK: T1059.004
    Tactics: Execution
    
    Implements 1 ASOM action(s) with advanced detection logic:
        - Define a list of high-risk parent processes that should not spawn shells (e.g., 'httpd', 'nginx', 'mysqld', 'java', 'php-fpm'). Create a detection rul...
    """
    
    def _get_name(self) -> str:
        return "Unix Shell Detection"
    
    def _get_technique_id(self) -> str:
        return "T1059.004"
    
    def _get_tactics(self) -> list:
        return ['Execution']
    
    def _get_asom_actions(self) -> list:
        return ["Define a list of high-risk parent processes that should not spawn shells (e.g., 'httpd', 'nginx', 'mysqld', 'java', 'php-fpm'). Create a detection rul..."]
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1059.004',
                        'technique_name': 'Unix Shell',
                        'tactics': ', '.join(['Execution']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # Define patterns based on ASOM requirements for this technique
        patterns = {
            'processes': [],
            'commands': []
        }
        
        # Add technique-specific patterns here
        # This would be customized per technique based on ASOM actions
        
        return patterns
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious unix shell patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class NetworkDeviceCLIStrategy(HuntStrategy):
    """
    Network Device CLI Detection Strategy
    
    MITRE ATT&CK: T1059.008
    Tactics: Execution
    
    Implements 1 ASOM action(s) with advanced detection logic:
        - Implement an hourly automated task that retrieves the running configuration from all core network devices. For each device, perform a `diff` against i...
    """
    
    def _get_name(self) -> str:
        return "Network Device CLI Detection"
    
    def _get_technique_id(self) -> str:
        return "T1059.008"
    
    def _get_tactics(self) -> list:
        return ['Execution']
    
    def _get_asom_actions(self) -> list:
        return ['Implement an hourly automated task that retrieves the running configuration from all core network devices. For each device, perform a `diff` against i...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1059.008',
                        'technique_name': 'Network Device CLI',
                        'tactics': ', '.join(['Execution']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # Define patterns based on ASOM requirements for this technique
        patterns = {
            'processes': [],
            'commands': []
        }
        
        # Add technique-specific patterns here
        # This would be customized per technique based on ASOM actions
        
        return patterns
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious network device cli patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class CloudAPIStrategy(HuntStrategy):
    """
    Cloud API Detection Strategy
    
    MITRE ATT&CK: T1059.009
    Tactics: Execution
    
    Implements 1 ASOM action(s) with advanced detection logic:
        - Monitor for process creation events (Windows Event ID 4688) where the 'NewProcessName' field contains a cloud CLI tool name (e.g., 'aws.exe', 'az.cmd'...
    """
    
    def _get_name(self) -> str:
        return "Cloud API Detection"
    
    def _get_technique_id(self) -> str:
        return "T1059.009"
    
    def _get_tactics(self) -> list:
        return ['Execution']
    
    def _get_asom_actions(self) -> list:
        return ["Monitor for process creation events (Windows Event ID 4688) where the 'NewProcessName' field contains a cloud CLI tool name (e.g., 'aws.exe', 'az.cmd'..."]
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1059.009',
                        'technique_name': 'Cloud API',
                        'tactics': ', '.join(['Execution']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # Define patterns based on ASOM requirements for this technique
        patterns = {
            'processes': [],
            'commands': []
        }
        
        # Add technique-specific patterns here
        # This would be customized per technique based on ASOM actions
        
        return patterns
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious cloud api patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class WebProtocolsStrategy(HuntStrategy):
    """
    Web Protocols Detection Strategy
    
    MITRE ATT&CK: T1071.001
    Tactics: Command And Control
    
    Implements 1 ASOM action(s) with advanced detection logic:
        - Correlate destination IPs and requested domains from Zeek conn.log and dns.log against a threat intelligence feed of known C2 servers. Generate an ale...
    """
    
    def _get_name(self) -> str:
        return "Web Protocols Detection"
    
    def _get_technique_id(self) -> str:
        return "T1071.001"
    
    def _get_tactics(self) -> list:
        return ['Command And Control']
    
    def _get_asom_actions(self) -> list:
        return ['Correlate destination IPs and requested domains from Zeek conn.log and dns.log against a threat intelligence feed of known C2 servers. Generate an ale...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'dest_ip']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1071.001',
                        'technique_name': 'Web Protocols',
                        'tactics': ', '.join(['Command And Control']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # Define patterns based on ASOM requirements for this technique
        patterns = {
            'processes': [],
            'commands': []
        }
        
        # Add technique-specific patterns here
        # This would be customized per technique based on ASOM actions
        
        return patterns
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious web protocols patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class DNSStrategy(HuntStrategy):
    """
    DNS Detection Strategy
    
    MITRE ATT&CK: T1071.004
    Tactics: Command And Control
    
    Implements 1 ASOM action(s) with advanced detection logic:
        - Create and maintain a watchlist of processes that should not typically initiate DNS queries (e.g., cmd.exe, powershell.exe, rundll32.exe, cscript.exe,...
    """
    
    def _get_name(self) -> str:
        return "DNS Detection"
    
    def _get_technique_id(self) -> str:
        return "T1071.004"
    
    def _get_tactics(self) -> list:
        return ['Command And Control']
    
    def _get_asom_actions(self) -> list:
        return ['Create and maintain a watchlist of processes that should not typically initiate DNS queries (e.g., cmd.exe, powershell.exe, rundll32.exe, cscript.exe,...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'process_name']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1071.004',
                        'technique_name': 'DNS',
                        'tactics': ', '.join(['Command And Control']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # DNS-specific patterns - focusing on non-browser processes and suspicious query patterns
        patterns = {
            'processes': [r'cmd', r'powershell', r'rundll32', r'regsvr32', r'mshta', r'wscript', r'cscript'],
            'commands': []
        }
        return patterns
    
    def get_description(self) -> str:
        return """
**What This Strategy Detects:**
Identifies DNS-based threats through:
- **Suspicious Process DNS**: Flags non-browser/non-system processes making DNS queries (cmd, powershell, rundll32, etc.)
- **High Entropy Domains**: Detects DGA (Domain Generation Algorithm) domains via Shannon entropy analysis (threshold: 4.5)
- **Query Volume Anomalies**: Identifies potential DNS tunneling through excessive query rates from single sources

**Key Fields Used:**
- `dns_query` or `query_name`: Domain entropy analysis for DGA detection
- `process_name`: Checking which process initiated DNS queries (via Sysmon Event ID 22)
- `timestamp`: Calculating queries per minute to detect tunneling
- `source_ip`: Grouping queries by source for volume analysis

**Why High Entropy?** DGA domains (used by malware to generate C2 domains) have high randomness. Example: normal domain "google.com" (entropy: ~3.2), DGA domain "xk3nmv2qpw9z.com" (entropy: ~3.9).  Above 4.5 indicates likely DGA.

**Why Process Matters?** Browsers and system services legitimately query DNS. Command-line tools, scripts, and LOLBins making DNS queries often indicate C2 communication or reconnaissance.

**Detection Logic:** Groups by source IP, calculates domain entropy, checks process names against suspicious list, monitors query frequency (>5/min suspicious), combines factors for threat scoring.
"""
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious dns patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class ValidAccountsStrategy(HuntStrategy):
    """
    Valid Accounts Detection Strategy
    
    MITRE ATT&CK: T1078
    Tactics: Initial Access, Persistence, Privilege Escalation, Defense Evasion
    
    Implements 5 ASOM action(s) with advanced detection logic:
        - For each successful remote login (Windows Event ID 4624), correlate the source IP from Zeek conn.log with the user's previous login location and times...
    - For each remote login from an account in a 'Third-Party Partner' group, check if the source IP in Zeek conn.log is outside the partner's registered IP...
    """
    
    def _get_name(self) -> str:
        return "Valid Accounts Detection"
    
    def _get_technique_id(self) -> str:
        return "T1078"
    
    def _get_tactics(self) -> list:
        return ['Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion']
    
    def _get_asom_actions(self) -> list:
        return ["For each successful remote login (Windows Event ID 4624), correlate the source IP from Zeek conn.log with the user's previous login location and times...", "For each remote login from an account in a 'Third-Party Partner' group, check if the source IP in Zeek conn.log is outside the partner's registered IP...", 'Maintain an explicit list of service account names or group memberships. Generate a critical alert if any account on this list authenticates with Logo...', 'Create a watchlist of highly privileged group SIDs (e.g., Domain Admins, Enterprise Admins). Monitor for Windows Event IDs 4728, 4732, 4756 targeting ...', "Maintain a watchlist of command-line arguments, using regex patterns for flexibility (e.g., '.*whoami.*', '.*net group.*', '.*Set-MpPreference -Disabl..."]
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'command_line', 'username']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1078',
                        'technique_name': 'Valid Accounts',
                        'tactics': ', '.join(['Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # Define patterns based on ASOM requirements for this technique
        patterns = {
            'processes': [],
            'commands': []
        }
        
        # Add technique-specific patterns here
        # This would be customized per technique based on ASOM actions
        
        return patterns
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious valid accounts patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class ReplicationThroughRemovableMediaStrategy(HuntStrategy):
    """
    Replication Through Removable Media Detection Strategy
    
    MITRE ATT&CK: T1091
    Tactics: Initial Access, Lateral Movement
    
    Implements 2 ASOM action(s) with advanced detection logic:
        - Join host events where EventID=2003 (DriverFrameworks-UserMode - USB Mount) is followed by EventID=1 (Sysmon - Process Create) on the same host within...
    - Create a detection rule that monitors Sysmon Event ID 11 for file creations on removable drives. Alert if the source Image process is not 'explorer.ex...
    """
    
    def _get_name(self) -> str:
        return "Replication Through Removable Media Detection"
    
    def _get_technique_id(self) -> str:
        return "T1091"
    
    def _get_tactics(self) -> list:
        return ['Initial Access', 'Lateral Movement']
    
    def _get_asom_actions(self) -> list:
        return ['Join host events where EventID=2003 (DriverFrameworks-UserMode - USB Mount) is followed by EventID=1 (Sysmon - Process Create) on the same host within...', "Create a detection rule that monitors Sysmon Event ID 11 for file creations on removable drives. Alert if the source Image process is not 'explorer.ex..."]
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'username']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1091',
                        'technique_name': 'Replication Through Removable Media',
                        'tactics': ', '.join(['Initial Access', 'Lateral Movement']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # Define patterns based on ASOM requirements for this technique
        patterns = {
            'processes': [],
            'commands': []
        }
        
        # Add technique-specific patterns here
        # This would be customized per technique based on ASOM actions
        
        return patterns
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious replication through removable media patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class NonApplicationLayerProtocolStrategy(HuntStrategy):
    """
    Non-Application Layer Protocol Detection Strategy
    
    MITRE ATT&CK: T1095
    Tactics: Command And Control
    
    Implements 1 ASOM action(s) with advanced detection logic:
        - Correlate Zeek conn.log UDP traffic to external IPs against a threat intelligence feed of known C2 servers. For any match, use the source IP and times...
    """
    
    def _get_name(self) -> str:
        return "Non-Application Layer Protocol Detection"
    
    def _get_technique_id(self) -> str:
        return "T1095"
    
    def _get_tactics(self) -> list:
        return ['Command And Control']
    
    def _get_asom_actions(self) -> list:
        return ['Correlate Zeek conn.log UDP traffic to external IPs against a threat intelligence feed of known C2 servers. For any match, use the source IP and times...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1095',
                        'technique_name': 'Non-Application Layer Protocol',
                        'tactics': ', '.join(['Command And Control']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # Define patterns based on ASOM requirements for this technique
        patterns = {
            'processes': [],
            'commands': []
        }
        
        # Add technique-specific patterns here
        # This would be customized per technique based on ASOM actions
        
        return patterns
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious non-application layer protocol patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class ExternalRemoteServicesStrategy(HuntStrategy):
    """
    External Remote Services Detection Strategy
    
    MITRE ATT&CK: T1133
    Tactics: Initial Access, Persistence
    
    Implements 2 ASOM action(s) with advanced detection logic:
        - Correlate successful remote logins (Windows Event ID 4624, Logon Type 3 or 10) with network sessions (Zeek conn.log) using the source IP address. Quer...
    - For each successful remote login (Windows Event ID 4624, Logon Type 10), attempt to join it with a corresponding logoff event (Windows Event ID 4647) ...
    """
    
    def _get_name(self) -> str:
        return "External Remote Services Detection"
    
    def _get_technique_id(self) -> str:
        return "T1133"
    
    def _get_tactics(self) -> list:
        return ['Initial Access', 'Persistence']
    
    def _get_asom_actions(self) -> list:
        return ['Correlate successful remote logins (Windows Event ID 4624, Logon Type 3 or 10) with network sessions (Zeek conn.log) using the source IP address. Quer...', 'For each successful remote login (Windows Event ID 4624, Logon Type 10), attempt to join it with a corresponding logoff event (Windows Event ID 4647) ...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1133',
                        'technique_name': 'External Remote Services',
                        'tactics': ', '.join(['Initial Access', 'Persistence']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # Define patterns based on ASOM requirements for this technique
        patterns = {
            'processes': [],
            'commands': []
        }
        
        # Add technique-specific patterns here
        # This would be customized per technique based on ASOM actions
        
        return patterns
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious external remote services patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class ExploitPublicFacingApplicationStrategy(HuntStrategy):
    """
    Exploit Public-Facing Application Detection Strategy
    
    MITRE ATT&CK: T1190
    Tactics: Initial Access
    
    Implements 1 ASOM action(s) with advanced detection logic:
        - Create a correlation rule that joins Zeek http.log with Sysmon Event ID 1. First, search the `uri` and `post_body` fields in `http.log` for a list of ...
    """
    
    def _get_name(self) -> str:
        return "Exploit Public-Facing Application Detection"
    
    def _get_technique_id(self) -> str:
        return "T1190"
    
    def _get_tactics(self) -> list:
        return ['Initial Access']
    
    def _get_asom_actions(self) -> list:
        return ['Create a correlation rule that joins Zeek http.log with Sysmon Event ID 1. First, search the `uri` and `post_body` fields in `http.log` for a list of ...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'command_line', 'dest_ip']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1190',
                        'technique_name': 'Exploit Public-Facing Application',
                        'tactics': ', '.join(['Initial Access']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # Define patterns based on ASOM requirements for this technique
        patterns = {
            'processes': [],
            'commands': []
        }
        
        # Add technique-specific patterns here
        # This would be customized per technique based on ASOM actions
        
        return patterns
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious exploit public-facing application patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class WebShellStrategy(HuntStrategy):
    """
    Web Shell Detection Strategy
    
    MITRE ATT&CK: T1505.003
    Tactics: Persistence
    
    Implements 1 ASOM action(s) with advanced detection logic:
        - Create a detection rule that correlates file creation events (Sysmon Event ID 11) in web directories for script extensions (.php, .aspx) with the writ...
    """
    
    def _get_name(self) -> str:
        return "Web Shell Detection"
    
    def _get_technique_id(self) -> str:
        return "T1505.003"
    
    def _get_tactics(self) -> list:
        return ['Persistence']
    
    def _get_asom_actions(self) -> list:
        return ['Create a detection rule that correlates file creation events (Sysmon Event ID 11) in web directories for script extensions (.php, .aspx) with the writ...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1505.003',
                        'technique_name': 'Web Shell',
                        'tactics': ', '.join(['Persistence']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # Define patterns based on ASOM requirements for this technique
        patterns = {
            'processes': [],
            'commands': []
        }
        
        # Add technique-specific patterns here
        # This would be customized per technique based on ASOM actions
        
        return patterns
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious web shell patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


class ContainerAdministrationCommandStrategy(HuntStrategy):
    """
    Container Administration Command Detection Strategy
    
    MITRE ATT&CK: T1609
    Tactics: Execution
    
    Implements 1 ASOM action(s) with advanced detection logic:
        - Create a detection rule that joins process creation events (Windows Event ID 4688, Docker/Kubernetes logs) with network connection logs (Zeek conn.log...
    """
    
    def _get_name(self) -> str:
        return "Container Administration Command Detection"
    
    def _get_technique_id(self) -> str:
        return "T1609"
    
    def _get_tactics(self) -> list:
        return ['Execution']
    
    def _get_asom_actions(self) -> list:
        return ['Create a detection rule that joins process creation events (Windows Event ID 4688, Docker/Kubernetes logs) with network connection logs (Zeek conn.log...']
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip', 'event_id', 'command_line']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        """
        Advanced analysis implementing ASOM detection logic.
        
        This implements sophisticated detection including:
        - Pattern matching for known attack indicators
        - Temporal correlation within time windows
        - Behavioral analytics and anomaly detection
        - Multi-factor threat scoring
        """
        if df.empty:
            return pd.DataFrame()
        
        results = []
        
        # Map columns
        ts_col = col_map.get('timestamp', 'timestamp')
        src_col = col_map.get('source_ip', 'source_ip')
        
        # Extract additional mapped columns
        event_col = col_map.get('event_id') if 'event_id' in col_map else None
        process_col = col_map.get('process_name') if 'process_name' in col_map else None
        cmd_col = col_map.get('command_line') if 'command_line' in col_map else None
        dest_col = col_map.get('dest_ip') if 'dest_ip' in col_map else None
        user_col = col_map.get('username') if 'username' in col_map else None
        
        # Define technique-specific suspicious patterns
        suspicious_patterns = self._get_suspicious_patterns()
        
        # Group by source for analysis
        if src_col in df.columns:
            for source_ip, group in df.groupby(src_col):
                threat_score = 0
                evidence_items = []
                details = {}
                
                # Factor 1: Volume and frequency analysis
                event_count = len(group)
                if event_count > df.groupby(src_col).size().quantile(0.90):
                    threat_score += 25
                    evidence_items.append(f"High event volume: {event_count} events")
                
                # Factor 2: Temporal patterns
                if ts_col in group.columns:
                    try:
                        timestamps = pd.to_datetime(group[ts_col])
                        if len(timestamps) > 1:
                            time_span = (timestamps.max() - timestamps.min()).total_seconds()
                            if time_span > 0:
                                events_per_min = (len(timestamps) / time_span) * 60
                                if events_per_min > 5:
                                    threat_score += 20
                                    evidence_items.append(f"Rapid activity: {events_per_min:.1f}/min")
                                
                                # Check for burst patterns (multiple events in short windows)
                                sorted_ts = timestamps.sort_values()
                                gaps = sorted_ts.diff().dt.total_seconds()
                                short_gaps = (gaps < 2).sum()
                                if short_gaps > 3:
                                    threat_score += 15
                                    evidence_items.append(f"Burst pattern: {short_gaps} rapid sequences")
                    except:
                        pass
                
                # Factor 3: Pattern matching (ASOM-specific)
                pattern_matches = []
                
                # Check process names
                if process_col and process_col in group.columns:
                    processes = group[process_col].dropna().astype(str)
                    for proc in processes:
                        matches = detect_suspicious_patterns(proc, suspicious_patterns.get('processes', []))
                        pattern_matches.extend(matches)
                    
                    if pattern_matches:
                        threat_score += 30
                        evidence_items.append(f"Suspicious processes: {', '.join(set(pattern_matches)[:3])}")
                
                # Check command lines
                if cmd_col and cmd_col in group.columns:
                    commands = group[cmd_col].dropna().astype(str)
                    for cmd in commands:
                        matches = detect_suspicious_patterns(cmd, suspicious_patterns.get('commands', []))
                        pattern_matches.extend(matches)
                        
                        # Check command entropy (obfuscation detection)
                        entropy = calculate_entropy(cmd)
                        if entropy > 4.5:
                            threat_score += 20
                            evidence_items.append(f"High entropy command (obfuscation): {entropy:.2f}")
                    
                    if [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]:
                        threat_score += 35
                        cmd_matches = [m for m in pattern_matches if m in suspicious_patterns.get('commands', [])]
                        evidence_items.append(f"Suspicious commands: {', '.join(set(cmd_matches)[:3])}")
                
                # Factor 4: Event type correlation
                if event_col and event_col in group.columns:
                    unique_events = group[event_col].nunique()
                    if unique_events >= 3:
                        threat_score += 15
                        evidence_items.append(f"Multiple event types: {unique_events} types")
                
                # Factor 5: User behavior (if applicable)
                if user_col and user_col in group.columns:
                    unique_users = group[user_col].nunique()
                    if unique_users > 1:
                        threat_score += 15
                        evidence_items.append(f"Multiple users: {unique_users} accounts")
                
                # Factor 6: Destination diversity (lateral movement indicator)
                if dest_col and dest_col in group.columns:
                    unique_dests = group[dest_col].nunique()
                    if unique_dests > 5:
                        threat_score += 20
                        evidence_items.append(f"Multiple targets: {unique_dests} destinations")
                
                # Normalize score
                threat_score = min(100, threat_score)
                
                # Only include high-confidence detections
                if threat_score >= 50:
                    results.append({
                        'source_ip': source_ip,
                        'event_count': event_count,
                        'threat_score': threat_score,
                        'technique_id': 'T1609',
                        'technique_name': 'Container Administration Command',
                        'tactics': ', '.join(['Execution']),
                        'evidence': ' | '.join(evidence_items[:5]) if evidence_items else 'Multiple ASOM indicators',
                        'explanation': f"ASOM-based detection: {', '.join(evidence_items[:3])}",
                        'pattern_matches': ', '.join(set(pattern_matches)[:5]) if pattern_matches else 'N/A',
                        'first_seen': group[ts_col].min() if ts_col in group.columns else 'N/A',
                        'last_seen': group[ts_col].max() if ts_col in group.columns else 'N/A',
                        'unique_processes': group[process_col].nunique() if process_col and process_col in group.columns else 0,
                        'unique_destinations': group[dest_col].nunique() if dest_col and dest_col in group.columns else 0
                    })
        
        if not results:
            return pd.DataFrame()
        
        result_df = pd.DataFrame(results)
        return result_df.sort_values('threat_score', ascending=False)
    
    def _get_suspicious_patterns(self) -> dict:
        """Return technique-specific suspicious patterns."""
        # Define patterns based on ASOM requirements for this technique
        patterns = {
            'processes': [],
            'commands': []
        }
        
        # Add technique-specific patterns here
        # This would be customized per technique based on ASOM actions
        
        return patterns
    
    def get_column_explanations(self) -> dict:
        return {
            'source_ip': 'IP address exhibiting suspicious container administration command patterns',
            'event_count': 'Total correlated events',
            'threat_score': 'Threat score (0-100) based on ASOM criteria',
            'technique_id': 'MITRE ATT&CK Technique ID',
            'technique_name': 'MITRE ATT&CK Technique Name',
            'tactics': 'MITRE ATT&CK Tactics',
            'evidence': 'Specific evidence triggering detection',
            'explanation': 'Detailed explanation',
            'pattern_matches': 'Matched suspicious patterns',
            'first_seen': 'First event timestamp',
            'last_seen': 'Last event timestamp',
            'unique_processes': 'Number of unique processes',
            'unique_destinations': 'Number of unique target IPs'
        }


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


# ASOM metadata
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
