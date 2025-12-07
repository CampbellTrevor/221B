"""
Test ML features in threat hunting strategies.

Tests the machine learning enhancements to verify they work correctly
with sufficient data and gracefully fall back when insufficient data.
"""

import unittest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from strategies import BeaconStrategy, EntropyStrategy, ExfilStrategy, HAS_SKLEARN


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
    
    def test_ml_column_explanations(self):
        """Test that ML columns have proper explanations."""
        strategies_to_test = [BeaconStrategy(), EntropyStrategy(), ExfilStrategy()]
        
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
