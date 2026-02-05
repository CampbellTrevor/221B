# Table Refresh Feature Guide

## Problem Solved

Previously, the dashboard would show "no available tables" or display stale cached data because:
- Tables were loaded only once at startup
- No mechanism existed to refresh the table list from the database
- The `_refresh_cache()` method existed but was never exposed in the UI

## Solution

A **"🔄 Refresh Tables"** button has been added to each strategy tab that allows users to:
- Force refresh the table list from the database
- Update all dropdown menus across all tabs
- Clear stale cache and query fresh data

## How to Use

### Location
The refresh button appears in the **"1️⃣ Select Data Source"** section of each strategy tab, right next to the "📊 Load Schema" button.

### Steps to Refresh Tables
1. Click any strategy tab (e.g., "Compromised", "DNSC2")
2. Look for the data source section at the top
3. Click the **"🔄 Refresh Tables"** button (yellow/warning style)
4. Wait for the refresh operation to complete
5. Check the output area for success message

### What Happens When You Click Refresh
1. **Cache Invalidation**: The local cache file (`.221b_cache/available_tables.json`) is deleted
2. **Database Query**: A fresh query is sent to the database via `information_schema.tables`
3. **Update Cache**: New table list is cached with current timestamp
4. **Update UI**: All table dropdowns in all strategy tabs are updated with the new list
5. **Preserve Selections**: If your currently selected table still exists, it remains selected

### Expected Output
```
🔄 Refreshing table list from database...
🔄 Manually refreshing table cache...
🔄 Querying database for available tables...
✅ Cached 45 tables
✅ Cache refreshed successfully!
✅ Successfully refreshed 45 tables across all tabs!
```

### When to Use Refresh
- When you see "No tables available" message
- After new tables are added to the database
- When the cache becomes stale (older than 7 days by default)
- After database schema changes
- When switching between different database environments

## Technical Details

### Cache Behavior
- **Cache Location**: `.221b_cache/available_tables.json`
- **Cache Duration**: 7 days by default (configurable)
- **Cache Format**: JSON with timestamp and table list
- **Automatic Refresh**: Cache auto-refreshes if older than 7 days

### Cache File Example
```json
{
  "timestamp": "2026-01-07T15:30:00",
  "tables": [
    "zeek_conn_c",
    "zeek_dns_c",
    "windows_security_c",
    "windows_sysmon_c"
  ]
}
```

### Code Changes
The following components were added:

1. **Button Widget**: Added to each strategy tab's `tab_data` dictionary
2. **Event Handler**: `_on_refresh_tables_click()` method handles button clicks
3. **UI Layout**: Button placed in HBox next to "Load Schema" button
4. **Update Logic**: Updates `self.all_tables` and all dropdown options

### Error Handling
If the refresh fails, you'll see an error message with details:
```
❌ Error refreshing tables: [error details]
[stack trace if applicable]
```

Common causes of errors:
- Database connection issues
- Authentication problems
- Network timeouts
- Database permissions

## Testing

A comprehensive test suite (`test_refresh_button.py`) verifies:
- ✅ Button exists in all strategy tabs
- ✅ Refresh updates the internal table list
- ✅ All dropdown widgets are updated
- ✅ Cache is properly invalidated
- ✅ Selections are preserved when possible

Run tests with:
```bash
python3 test_refresh_button.py
```

## Benefits

### For Users
- **No Restart Required**: Refresh tables without restarting the dashboard
- **Quick Recovery**: Fix "no tables available" issues instantly
- **Always Current**: Ensure you're working with the latest database schema
- **Better UX**: Clear visual feedback during refresh operation

### For Developers
- **Reusable Method**: `_refresh_cache()` can be called programmatically
- **Consistent State**: All tabs stay synchronized after refresh
- **Error Resilient**: Graceful handling of database connection issues
- **Well Tested**: Comprehensive test coverage ensures reliability

## Troubleshooting

### Problem: Button doesn't appear
**Solution**: Ensure you're using the latest version of `app.py` that includes the refresh button code.

### Problem: Refresh returns "No tables available"
**Solution**: Check database connection settings and ensure your user has permissions to query `information_schema.tables`.

### Problem: Tables appear but then disappear
**Solution**: This suggests the database query succeeded initially but failed on refresh. Check database logs for connection issues.

### Problem: Selected table is lost after refresh
**Solution**: This is expected if the table no longer exists in the database. The refresh preserves selections only for tables that still exist.

## Related Files
- `app.py` - Main dashboard code with refresh functionality
- `.221b_cache/available_tables.json` - Cache file (auto-generated)
- `test_refresh_button.py` - Test suite for refresh functionality
- `ionic_scripting_framework.py` - Database connection module

## Configuration Options

You can customize cache behavior when creating the dashboard:

```python
from app import WatsonDashboard
from strategies import get_all_strategies

strategies = get_all_strategies()

# Customize cache settings
dashboard = WatsonDashboard(
    strategies,
    cache_dir='.my_custom_cache',  # Custom cache directory
    cache_days=3                     # Cache expires after 3 days
)

dashboard.display()
```

## Future Enhancements

Possible improvements for future versions:
- [ ] Auto-refresh on a schedule
- [ ] Show cache age in the UI
- [ ] Keyboard shortcut for refresh
- [ ] Refresh individual tables vs all tables
- [ ] Progress indicator during refresh
- [ ] Cache size and cleanup utilities
