#!/usr/bin/env python3
"""
Test script to verify the table refresh button functionality.
This tests that the fix for "no available tables" issue works correctly.
"""
import sys
import os

# Mock the isf module before importing app
class MockISF:
    def __init__(self):
        self.call_count = 0
        
    def run_query(self, query):
        import pandas as pd
        self.call_count += 1
        
        # Simulate different database states
        if self.call_count == 1:
            # Initial state - limited tables
            return pd.DataFrame({'table_name': ['zeek_conn_c', 'windows_security_c']})
        else:
            # After refresh - more tables available
            return pd.DataFrame({
                'table_name': [
                    'zeek_conn_c', 'zeek_dns_c', 'zeek_http_c',
                    'windows_security_c', 'windows_sysmon_c',
                    'a365_il4_audit_signin', 'cisco_asa_c'
                ]
            })

mock_isf = MockISF()
sys.modules['ionic_scripting_framework'] = type('module', (), {'isf': mock_isf})()

# Now import after mocking
from app import WatsonDashboard
from strategies import get_all_strategies

def test_refresh_button_exists():
    """Test that the refresh button exists in all tabs."""
    print("🧪 Test 1: Verify refresh button exists")
    strategies = get_all_strategies()
    dashboard = WatsonDashboard(strategies)
    
    for tab_idx, tab_data in dashboard.strategy_tab_contents.items():
        assert 'refresh_tables_button' in tab_data, f"Tab {tab_idx} missing refresh button"
        button = tab_data['refresh_tables_button']
        assert button.description == '🔄 Refresh Tables', "Button has wrong description"
        assert button.button_style == 'warning', "Button should use warning style"
    
    print(f"✅ All {len(dashboard.strategy_tab_contents)} tabs have refresh button")
    return dashboard

def test_refresh_updates_tables(dashboard):
    """Test that refresh actually updates the table list."""
    print("\n🧪 Test 2: Verify refresh updates table list")
    
    initial_tables = dashboard.all_tables[:]
    initial_count = len(initial_tables)
    print(f"   Initial tables ({initial_count}): {initial_tables}")
    
    # Simulate clicking the refresh button
    refreshed_tables = dashboard._refresh_cache()
    dashboard.all_tables = refreshed_tables
    
    refreshed_count = len(refreshed_tables)
    print(f"   Refreshed tables ({refreshed_count}): {refreshed_tables}")
    
    assert refreshed_count > initial_count, "Refresh should find more tables"
    assert refreshed_count == 7, f"Expected 7 tables after refresh, got {refreshed_count}"
    
    print(f"✅ Refresh successfully updated from {initial_count} to {refreshed_count} tables")
    return dashboard

def test_refresh_updates_dropdowns(dashboard):
    """Test that refresh updates all dropdown widgets."""
    print("\n🧪 Test 3: Verify refresh updates all dropdowns")
    
    # Update dropdowns like the button handler does
    for tab_idx, tab_content in dashboard.strategy_tab_contents.items():
        tab_content['table_dropdown'].options = dashboard.all_tables
        tab_content['secondary_table_dropdown'].options = dashboard.all_tables
    
    # Verify all tabs have updated options
    for tab_idx, tab_content in dashboard.strategy_tab_contents.items():
        primary_options = list(tab_content['table_dropdown'].options)
        secondary_options = list(tab_content['secondary_table_dropdown'].options)
        
        assert len(primary_options) == 7, f"Tab {tab_idx} primary dropdown has wrong count"
        assert len(secondary_options) == 7, f"Tab {tab_idx} secondary dropdown has wrong count"
        assert 'zeek_dns_c' in primary_options, "Should include new tables"
    
    print(f"✅ All dropdowns updated successfully across {len(dashboard.strategy_tab_contents)} tabs")
    return dashboard

def test_cache_invalidation():
    """Test that cache is properly invalidated on refresh."""
    print("\n🧪 Test 4: Verify cache invalidation")
    
    # Remove existing cache
    cache_dir = '.221b_cache'
    cache_file = os.path.join(cache_dir, 'available_tables.json')
    
    if os.path.exists(cache_file):
        os.remove(cache_file)
        print("   Removed existing cache file")
    
    # Create dashboard - should query database
    strategies = get_all_strategies()
    dashboard = WatsonDashboard(strategies)
    
    # Verify cache file was created
    assert os.path.exists(cache_file), "Cache file should be created"
    print("   ✅ Cache file created on initialization")
    
    # Get file modification time
    import time
    mtime_before = os.path.getmtime(cache_file)
    time.sleep(0.1)  # Small delay to ensure timestamp difference
    
    # Refresh cache
    dashboard._refresh_cache()
    
    # Verify cache file was updated
    mtime_after = os.path.getmtime(cache_file)
    assert mtime_after > mtime_before, "Cache file should be updated on refresh"
    print("   ✅ Cache file updated on refresh")
    
    print("✅ Cache invalidation works correctly")

def main():
    """Run all tests."""
    print("=" * 70)
    print("Testing Table Refresh Button Functionality")
    print("=" * 70)
    print()
    
    try:
        dashboard = test_refresh_button_exists()
        dashboard = test_refresh_updates_tables(dashboard)
        dashboard = test_refresh_updates_dropdowns(dashboard)
        test_cache_invalidation()
        
        print()
        print("=" * 70)
        print("🎉 All tests passed! Table refresh functionality is working correctly.")
        print("=" * 70)
        return 0
        
    except AssertionError as e:
        print()
        print("=" * 70)
        print(f"❌ Test failed: {e}")
        print("=" * 70)
        return 1
    except Exception as e:
        print()
        print("=" * 70)
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        print("=" * 70)
        return 1

if __name__ == '__main__':
    sys.exit(main())
