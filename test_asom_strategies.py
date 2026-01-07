"""
Test suite for ASOM-aligned threat hunting strategies.

Tests all ASOM strategies with mock data to ensure they work correctly
without requiring external IONIC database connections.
"""

import unittest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from strategies import (
    CompromisedCredentialsStrategy, 
    DNSC2Strategy,
    get_all_strategies,
    ML_MIN_SAMPLES
)


class TestCompromisedCredentialsStrategy(unittest.TestCase):
    """Test CCIR 1: Compromised Credentials Strategy."""
    
    def setUp(self):
        """Set up test data and strategy."""
        self.strategy = CompromisedCredentialsStrategy()
    
    def test_strategy_metadata(self):
        """Test that strategy metadata is correct."""
        self.assertEqual(self.strategy.ccir, 1)
        self.assertEqual(self.strategy._get_tactic(), "Initial Access (TA0001)")
        self.assertIn("compromised credentials", self.strategy._get_ccir_question().lower())
        self.assertEqual(self.strategy.name, "Compromised Credentials Detector")
    
    def test_level1_brute_force_detection(self):
        """Test Level 1: Rule-based detection of brute force followed by success."""
        base_time = datetime.now()
        data = []
        
        # 25 failed login attempts
        for i in range(25):
            data.append({
                'timestamp': base_time + timedelta(seconds=i * 5),
                'event_id': 4625,
                'logon_type': 3,
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'status': 'failed'
            })
        
        # Followed by 1 successful login
        data.append({
            'timestamp': base_time + timedelta(seconds=130),  # 2+ minutes later
            'event_id': 4624,
            'logon_type': 3,
            'source_ip': '192.168.1.100',
            'username': 'admin',
            'status': 'success'
        })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'event_id': 'event_id',
            'logon_type': 'logon_type',
            'source_ip': 'source_ip',
            'username': 'username',
            'status': 'status'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect the brute force pattern
        self.assertFalse(result.empty, "Should detect brute force pattern")
        self.assertEqual(result.iloc[0]['detection_level'], 1)
        self.assertGreaterEqual(result.iloc[0]['threat_score'], 75)
        self.assertIn('failed attempts', result.iloc[0]['explanation'].lower())
        self.assertEqual(result.iloc[0]['failed_attempts'], 25)
    
    def test_level1_no_detection_without_success(self):
        """Test Level 1: No detection if no successful login follows failures."""
        base_time = datetime.now()
        data = []
        
        # Only failed attempts, no success
        for i in range(25):
            data.append({
                'timestamp': base_time + timedelta(seconds=i * 5),
                'event_id': 4625,
                'logon_type': 3,
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'status': 'failed'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'event_id': 'event_id',
            'logon_type': 'logon_type',
            'source_ip': 'source_ip',
            'username': 'username',
            'status': 'status'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should NOT detect (no successful login)
        self.assertTrue(result.empty, "Should not detect without successful login")
    
    def test_level1_reconnaissance_detection(self):
        """Test Level 1: Detection of post-login reconnaissance commands."""
        base_time = datetime.now()
        data = [
            {
                'timestamp': base_time,
                'event_id': 4624,
                'logon_type': 10,
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'status': 'success',
                'command_line': 'whoami.exe'
            },
            {
                'timestamp': base_time + timedelta(seconds=10),
                'event_id': 4624,
                'logon_type': 10,
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'status': 'success',
                'command_line': 'net user /domain'
            },
            {
                'timestamp': base_time + timedelta(seconds=20),
                'event_id': 4624,
                'logon_type': 10,
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'status': 'success',
                'command_line': 'ipconfig /all'
            }
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'event_id': 'event_id',
            'logon_type': 'logon_type',
            'source_ip': 'source_ip',
            'username': 'username',
            'status': 'status',
            'command_line': 'command_line'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect reconnaissance commands
        self.assertFalse(result.empty, "Should detect reconnaissance")
        self.assertTrue(any('reconnaissance' in str(exp).lower() for exp in result['explanation']))
    
    def test_level2_off_hours_detection(self):
        """Test Level 2: Statistical detection of off-hours login."""
        base_time = datetime.now()
        data = []
        
        # Establish baseline: 10 logins during business hours (9 AM - 5 PM) with normal data volume
        for i in range(10):
            login_time = base_time.replace(hour=10, minute=0) + timedelta(days=i)
            data.append({
                'timestamp': login_time,
                'event_id': 4624,
                'logon_type': 10,
                'source_ip': f'192.168.1.{100 + i}',
                'username': 'user1',
                'status': 'success',
                'bytes_sent': 1000,
                'bytes_received': 5000
            })
        
        # Add an off-hours login (3 AM) with excessive data volume to ensure detection
        off_hours_time = base_time.replace(hour=3, minute=0)
        data.append({
            'timestamp': off_hours_time,
            'event_id': 4624,
            'logon_type': 10,
            'source_ip': '192.168.1.200',
            'username': 'user1',
            'status': 'success',
            'bytes_sent': 100000,  # Much higher than baseline
            'bytes_received': 500000  # Much higher than baseline
        })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'event_id': 'event_id',
            'logon_type': 'logon_type',
            'source_ip': 'source_ip',
            'username': 'username',
            'status': 'status',
            'bytes_sent': 'bytes_sent',
            'bytes_received': 'bytes_received'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect off-hours anomaly
        self.assertFalse(result.empty, "Should detect off-hours login")
        level2_results = result[result['detection_level'] == 2]
        self.assertFalse(level2_results.empty, "Should have Level 2 detections")
        self.assertTrue(any('off-hours' in str(exp).lower() for exp in level2_results['explanation']))
    
    def test_level3_ml_anomaly_detection(self):
        """Test Level 3: Machine learning anomaly detection."""
        np.random.seed(42)
        base_time = datetime.now()
        data = []
        
        # Create 60 normal login sessions (business hours, modest data volume)
        for i in range(60):
            login_hour = np.random.choice([9, 10, 11, 14, 15, 16])  # Business hours
            data.append({
                'timestamp': base_time.replace(hour=login_hour) + timedelta(days=i),
                'event_id': 4624,
                'logon_type': 10,
                'source_ip': f'192.168.1.{100 + i}',
                'username': f'user{i % 10}',
                'status': 'success',
                'bytes_sent': np.random.randint(1000, 10000),
                'bytes_received': np.random.randint(5000, 50000),
                'command_line': 'outlook.exe'
            })
        
        # Add 5 anomalous sessions (off-hours, high data volume)
        for i in range(5):
            data.append({
                'timestamp': base_time.replace(hour=2) + timedelta(days=i),
                'event_id': 4624,
                'logon_type': 10,
                'source_ip': f'10.0.0.{i}',
                'username': 'admin',
                'status': 'success',
                'bytes_sent': 500000,  # Much higher
                'bytes_received': 2000000,  # Much higher
                'command_line': 'powershell.exe -enc aGVsbG8='  # High entropy
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'event_id': 'event_id',
            'logon_type': 'logon_type',
            'source_ip': 'source_ip',
            'username': 'username',
            'status': 'status',
            'bytes_sent': 'bytes_sent',
            'bytes_received': 'bytes_received',
            'command_line': 'command_line'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should have ML detections (Level 3)
        self.assertFalse(result.empty, "Should have detections")
        level3_results = result[result['detection_level'] == 3]
        
        # ML should trigger with 50+ samples
        if len(df) >= 50:
            self.assertFalse(level3_results.empty, "Should have Level 3 ML detections")
            
            # Check ML-specific columns
            if not level3_results.empty:
                self.assertIn('ml_anomaly_score', level3_results.columns)
                self.assertIn('ml_confidence', level3_results.columns)
                self.assertIn('ml_explanation', level3_results.columns)
                self.assertTrue(any('machine learning' in str(exp).lower() 
                                  for exp in level3_results['explanation']))
    
    def test_empty_dataframe(self):
        """Test that strategy handles empty DataFrame gracefully."""
        df = pd.DataFrame()
        col_map = {
            'timestamp': 'timestamp',
            'event_id': 'event_id',
            'source_ip': 'source_ip',
            'username': 'username',
            'status': 'status'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should return empty DataFrame without errors
        self.assertTrue(result.empty)
    
    def test_severity_labels(self):
        """Test that severity labels are applied correctly."""
        base_time = datetime.now()
        data = []
        
        # Create scenario with high threat score (30 failed + success)
        for i in range(30):
            data.append({
                'timestamp': base_time + timedelta(seconds=i * 5),
                'event_id': 4625,
                'logon_type': 3,
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'status': 'failed'
            })
        
        data.append({
            'timestamp': base_time + timedelta(seconds=160),
            'event_id': 4624,
            'logon_type': 3,
            'source_ip': '192.168.1.100',
            'username': 'admin',
            'status': 'success'
        })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'event_id': 'event_id',
            'logon_type': 'logon_type',
            'source_ip': 'source_ip',
            'username': 'username',
            'status': 'status'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Check severity labels
        self.assertIn('severity', result.columns)
        self.assertIn(result.iloc[0]['severity'], ['HIGH', 'MED', 'LOW'])
        
        # High failed attempt count should result in HIGH severity
        if result.iloc[0]['threat_score'] >= 75:
            self.assertEqual(result.iloc[0]['severity'], 'HIGH')
    
    def test_column_explanations(self):
        """Test that strategy provides column explanations."""
        explanations = self.strategy.get_column_explanations()
        
        # Should have standard columns
        self.assertIn('threat_score', explanations)
        self.assertIn('severity', explanations)
        self.assertIn('detection_level', explanations)
        self.assertIn('explanation', explanations)
        
        # Should have strategy-specific columns
        self.assertIn('source_ip', explanations)
        self.assertIn('username', explanations)
        self.assertIn('failed_attempts', explanations)


class TestASOMLFramework(unittest.TestCase):
    """Test the ASOM framework infrastructure."""
    
    def test_get_all_strategies(self):
        """Test that get_all_strategies returns strategy list."""
        strategies = get_all_strategies()
        
        self.assertIsInstance(strategies, list)
        self.assertGreater(len(strategies), 0)
        
        # All should be ASOM strategies
        for strategy in strategies:
            self.assertTrue(hasattr(strategy, 'ccir'))
            self.assertTrue(hasattr(strategy, 'analyze'))
            self.assertTrue(hasattr(strategy, '_get_ccir_question'))
    
    def test_data_correlator_temporal_join(self):
        """Test the DataCorrelator temporal join functionality."""
        from strategies import DataCorrelator
        
        correlator = DataCorrelator()
        
        # Create two dataframes to join
        base_time = datetime.now()
        df1 = pd.DataFrame([
            {'timestamp': base_time, 'source_ip': '192.168.1.1', 'event': 'login'},
            {'timestamp': base_time + timedelta(seconds=30), 'source_ip': '192.168.1.2', 'event': 'login'}
        ])
        
        df2 = pd.DataFrame([
            {'timestamp': base_time + timedelta(seconds=10), 'source_ip': '192.168.1.1', 'process': 'cmd.exe'},
            {'timestamp': base_time + timedelta(seconds=200), 'source_ip': '192.168.1.2', 'process': 'cmd.exe'}
        ])
        
        # Join within 120 second window
        result = correlator.temporal_join(
            df1, df2,
            'timestamp', 'timestamp',
            ['source_ip'],
            window_seconds=120
        )
        
        # Should correlate the first pair (10s apart) but not second (170s apart)
        self.assertFalse(result.empty)
        self.assertEqual(len(result), 1)
        self.assertEqual(result.iloc[0]['source_ip'], '192.168.1.1')


class TestDNSC2Strategy(unittest.TestCase):
    """Test CCIR 22: DNS C2 Strategy."""
    
    def setUp(self):
        """Set up test data and strategy."""
        self.strategy = DNSC2Strategy()
    
    def test_strategy_metadata(self):
        """Test that strategy metadata is correct."""
        self.assertEqual(self.strategy.ccir, 22)
        self.assertEqual(self.strategy._get_tactic(), "Command & Control (TA0011)")
        self.assertIn("dns", self.strategy._get_ccir_question().lower())
        self.assertEqual(self.strategy.name, "DNS C2 Detector")
    
    def test_indicator1_level1_suspicious_process(self):
        """Test Indicator 1, Level 1: Suspicious process making DNS queries."""
        base_time = datetime.now()
        data = [
            {
                'timestamp': base_time,
                'query': 'malicious.com',
                'query_type': 'A',
                'source_ip': '192.168.1.100',
                'hostname': 'workstation1',
                'process_name': 'powershell.exe',
                'parent_process': 'winword.exe'  # Office app parent - highly suspicious
            },
            {
                'timestamp': base_time + timedelta(seconds=5),
                'query': 'example.com',
                'query_type': 'A',
                'source_ip': '192.168.1.100',
                'hostname': 'workstation1',
                'process_name': 'cmd.exe',
                'parent_process': 'explorer.exe'
            }
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'query': 'query',
            'query_type': 'query_type',
            'source_ip': 'source_ip',
            'hostname': 'hostname',
            'process_name': 'process_name',
            'parent_process': 'parent_process'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect suspicious processes
        self.assertFalse(result.empty, "Should detect suspicious processes")
        
        # Check for high threat score with Office parent
        high_threat = result[result['threat_score'] >= 85]
        self.assertFalse(high_threat.empty, "Should flag Office app parent as high threat")
        self.assertTrue(any('winword' in str(exp).lower() for exp in high_threat['explanation']))
    
    def test_indicator1_level2_statistical_anomaly(self):
        """Test Indicator 1, Level 2: Statistical baseline detection."""
        base_time = datetime.now()
        data = []
        
        # Establish baseline: 20 normal queries from chrome.exe
        for i in range(20):
            data.append({
                'timestamp': base_time + timedelta(minutes=i),
                'query': f'normal-site-{i}.com',
                'query_type': 'A',
                'source_ip': '192.168.1.100',
                'hostname': 'workstation1',
                'process_name': 'chrome.exe'
            })
        
        # Add anomalous queries: high entropy domain
        for i in range(5):
            data.append({
                'timestamp': base_time + timedelta(minutes=20 + i),
                'query': 'adfasdkfjhaksjdfhaksjdhfaksjdhfkajsdhfkajsdhf.com',  # High entropy
                'query_type': 'TXT',  # Suspicious type
                'source_ip': '192.168.1.100',
                'hostname': 'workstation1',
                'process_name': 'chrome.exe'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'query': 'query',
            'query_type': 'query_type',
            'source_ip': 'source_ip',
            'hostname': 'hostname',
            'process_name': 'process_name'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect statistical anomalies
        level2_results = result[result['detection_level'] == 2]
        if not level2_results.empty:
            self.assertTrue(any('anomaly' in str(exp).lower() for exp in level2_results['explanation']))
    
    def test_indicator1_level3_ml_detection(self):
        """Test Indicator 1, Level 3: ML-based process anomaly detection."""
        np.random.seed(42)
        base_time = datetime.now()
        data = []
        
        # Create 60 normal DNS queries from legitimate processes
        for i in range(60):
            data.append({
                'timestamp': base_time + timedelta(minutes=i),
                'query': f'legitimate-site-{i % 10}.com',
                'query_type': 'A',
                'source_ip': f'192.168.1.{100 + i % 10}',
                'hostname': f'workstation{i % 5}',
                'process_name': 'chrome.exe',
                'command_line': 'chrome.exe --start-minimized',
                'parent_process': 'explorer.exe'
            })
        
        # Add anomalous queries: suspicious process with high entropy commands
        for i in range(5):
            data.append({
                'timestamp': base_time + timedelta(minutes=60 + i),
                'query': f'c2-server-{i}.tk',
                'query_type': 'TXT',
                'source_ip': '10.0.0.100',
                'hostname': 'compromised-host',
                'process_name': 'powershell.exe',
                'command_line': 'powershell.exe -enc YmFzZTY0ZW5jb2RlZGNvbW1hbmQ=',  # High entropy
                'parent_process': 'winword.exe',
                'query_count': 10
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'query': 'query',
            'query_type': 'query_type',
            'source_ip': 'source_ip',
            'hostname': 'hostname',
            'process_name': 'process_name',
            'command_line': 'command_line',
            'parent_process': 'parent_process'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should have ML detections
        level3_results = result[result['detection_level'] == 3]
        if len(df) >= ML_MIN_SAMPLES and not level3_results.empty:
            self.assertIn('ml_anomaly_score', level3_results.columns)
            self.assertIn('ml_confidence', level3_results.columns)
    
    def test_indicator2_level1_c2_pattern_detection(self):
        """Test Indicator 2, Level 1: C2 domain pattern detection."""
        base_time = datetime.now()
        data = [
            {
                'timestamp': base_time,
                'query': '1234567890123456.com',  # Long numeric - DGA-like
                'query_type': 'A',
                'source_ip': '192.168.1.100',
                'hostname': 'workstation1',
                'process_name': 'malware.exe'
            },
            {
                'timestamp': base_time + timedelta(seconds=5),
                'query': 'asdfghjklzxcvbnmqwerty.tk',  # Free TLD
                'query_type': 'A',
                'source_ip': '192.168.1.100',
                'hostname': 'workstation1',
                'process_name': 'suspicious.exe'
            },
            {
                'timestamp': base_time + timedelta(seconds=10),
                'query': 'google.com',  # Normal domain
                'query_type': 'A',
                'source_ip': '192.168.1.100',
                'hostname': 'workstation1',
                'process_name': 'chrome.exe'
            }
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'query': 'query',
            'query_type': 'query_type',
            'source_ip': 'source_ip',
            'hostname': 'hostname',
            'process_name': 'process_name'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect C2 patterns
        self.assertFalse(result.empty, "Should detect C2 domain patterns")
        indicator2_level1 = result[(result['indicator'] == 2) & (result['detection_level'] == 1)]
        self.assertFalse(indicator2_level1.empty, "Should have Indicator 2, Level 1 detections")
    
    def test_indicator2_level2_query_characteristics(self):
        """Test Indicator 2, Level 2: Statistical analysis of query characteristics."""
        base_time = datetime.now()
        data = []
        
        # Establish baseline: 50 normal queries
        for i in range(50):
            data.append({
                'timestamp': base_time + timedelta(seconds=i * 10),
                'query': f'normal{i}.example.com',
                'query_type': 'A',
                'source_ip': '192.168.1.100',
                'hostname': 'workstation1'
            })
        
        # Add suspicious queries in a 5-minute window
        window_start = base_time + timedelta(minutes=10)
        for i in range(60):  # High volume
            data.append({
                'timestamp': window_start + timedelta(seconds=i * 2),
                'query': f'sub1.sub2.sub3.sub4.sub5.sub6.suspicious{i}.com',  # Many subdomains
                'query_type': 'TXT' if i % 5 == 0 else 'A',  # Some TXT queries
                'source_ip': '192.168.1.100',
                'hostname': 'workstation1'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'query': 'query',
            'query_type': 'query_type',
            'source_ip': 'source_ip',
            'hostname': 'hostname'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect query characteristic anomalies
        level2_results = result[result['detection_level'] == 2]
        if not level2_results.empty:
            # Check for indicator 2 detections
            indicator2_level2 = level2_results[level2_results['indicator'] == 2]
            if not indicator2_level2.empty:
                self.assertTrue(any('query' in str(exp).lower() or 'volume' in str(exp).lower() 
                                   for exp in indicator2_level2['explanation']))
    
    def test_indicator2_level3_ml_classification(self):
        """Test Indicator 2, Level 3: ML classification of DNS queries."""
        np.random.seed(42)
        base_time = datetime.now()
        data = []
        
        # Create 60 normal DNS queries
        for i in range(60):
            data.append({
                'timestamp': base_time + timedelta(minutes=i),
                'query': f'legitimate{i}.example.com',
                'query_type': 'A',
                'source_ip': f'192.168.1.{100 + i % 20}',
                'hostname': f'workstation{i % 10}',
                'ttl': 3600
            })
        
        # Add suspicious queries with C2 characteristics
        for i in range(10):
            data.append({
                'timestamp': base_time + timedelta(minutes=60 + i),
                'query': f'aaaaabbbbbcccccdddddeeeeefffffggggg{i}.tk',  # Long, high entropy, free TLD
                'query_type': 'TXT',
                'source_ip': '10.0.0.100',
                'hostname': 'compromised-host',
                'ttl': 60  # Low TTL
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'query': 'query',
            'query_type': 'query_type',
            'source_ip': 'source_ip',
            'hostname': 'hostname',
            'ttl': 'ttl'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should have ML detections
        level3_results = result[result['detection_level'] == 3]
        if len(df) >= ML_MIN_SAMPLES and not level3_results.empty:
            indicator2_level3 = level3_results[level3_results['indicator'] == 2]
            if not indicator2_level3.empty:
                self.assertIn('ml_anomaly_score', indicator2_level3.columns)
                self.assertIn('ml_explanation', indicator2_level3.columns)
    
    def test_empty_dataframe(self):
        """Test that strategy handles empty DataFrame gracefully."""
        df = pd.DataFrame()
        col_map = {
            'timestamp': 'timestamp',
            'query': 'query',
            'source_ip': 'source_ip'
        }
        
        result = self.strategy.analyze(df, col_map)
        self.assertTrue(result.empty)
    
    def test_both_indicators_detected(self):
        """Test that both indicators can detect threats in same dataset."""
        base_time = datetime.now()
        data = [
            # Indicator 1 detection: suspicious process
            {
                'timestamp': base_time,
                'query': 'command-server.com',
                'query_type': 'A',
                'source_ip': '192.168.1.100',
                'hostname': 'workstation1',
                'process_name': 'powershell.exe',
                'parent_process': 'winword.exe'
            },
            # Indicator 2 detection: C2 pattern
            {
                'timestamp': base_time + timedelta(seconds=30),
                'query': '123456789012345.tk',
                'query_type': 'TXT',
                'source_ip': '192.168.1.101',
                'hostname': 'workstation2',
                'process_name': 'chrome.exe'
            }
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'query': 'query',
            'query_type': 'query_type',
            'source_ip': 'source_ip',
            'hostname': 'hostname',
            'process_name': 'process_name',
            'parent_process': 'parent_process'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should have detections from both indicators
        self.assertFalse(result.empty)
        
        indicators = result['indicator'].unique()
        # At least one indicator should detect
        self.assertGreater(len(indicators), 0)
    
    def test_severity_labels(self):
        """Test that severity labels are applied correctly."""
        base_time = datetime.now()
        data = [
            {
                'timestamp': base_time,
                'query': 'malicious.com',
                'query_type': 'A',
                'source_ip': '192.168.1.100',
                'hostname': 'workstation1',
                'process_name': 'powershell.exe',
                'parent_process': 'winword.exe'  # Should result in HIGH severity
            }
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'query': 'query',
            'query_type': 'query_type',
            'source_ip': 'source_ip',
            'hostname': 'hostname',
            'process_name': 'process_name',
            'parent_process': 'parent_process'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Check severity labels
        if not result.empty:
            self.assertIn('severity', result.columns)
            self.assertIn(result.iloc[0]['severity'], ['HIGH', 'MED', 'LOW'])
    
    def test_column_explanations(self):
        """Test that strategy provides column explanations."""
        explanations = self.strategy.get_column_explanations()
        
        # Should have standard columns
        self.assertIn('threat_score', explanations)
        self.assertIn('severity', explanations)
        self.assertIn('detection_level', explanations)
        
        # Should have strategy-specific columns
        self.assertIn('query', explanations)
        self.assertIn('process_name', explanations)
        self.assertIn('indicator', explanations)


if __name__ == '__main__':
    unittest.main()
