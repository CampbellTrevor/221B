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
    TunnelingStrategy
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


class TestStrategyRequirements(unittest.TestCase):
    """Test that all strategies meet basic requirements."""
    
    def test_all_strategies_have_names(self):
        """Test that all strategies have names."""
        strategies = [
            BeaconStrategy(),
            EntropyStrategy(),
            ExfilStrategy(),
            PortScanStrategy(),
            BruteForceStrategy(),
            TunnelingStrategy()
        ]
        
        for strategy in strategies:
            self.assertIsNotNone(strategy.name)
            self.assertGreater(len(strategy.name), 0)
    
    def test_all_strategies_have_required_inputs(self):
        """Test that all strategies define required inputs."""
        strategies = [
            BeaconStrategy(),
            EntropyStrategy(),
            ExfilStrategy(),
            PortScanStrategy(),
            BruteForceStrategy(),
            TunnelingStrategy()
        ]
        
        for strategy in strategies:
            self.assertIsNotNone(strategy.required_inputs)
            self.assertGreater(len(strategy.required_inputs), 0)
    
    def test_all_strategies_have_explanations(self):
        """Test that all strategies provide column explanations."""
        strategies = [
            BeaconStrategy(),
            EntropyStrategy(),
            ExfilStrategy(),
            PortScanStrategy(),
            BruteForceStrategy(),
            TunnelingStrategy()
        ]
        
        for strategy in strategies:
            explanations = strategy.get_column_explanations()
            self.assertIsNotNone(explanations)
            self.assertGreater(len(explanations), 0)


if __name__ == '__main__':
    unittest.main()
