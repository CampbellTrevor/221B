# 221B - Interactive Threat Hunting Dashboard

A Jupyter notebook-based threat hunting platform that provides interactive analysis of network security data through pre-built detection strategies.

## Overview

221B is a no-code threat hunting tool designed for security analysts to investigate network traffic and detect malicious behavior patterns. It connects to IONIC data stores via the `ionic_scripting_framework` and provides an intuitive widget-based interface for running various threat detection strategies.

### 🆕 What's New in This Release

**Expanded Detection Coverage:**
- 3 new advanced threat hunting strategies (Lateral Movement, Data Hoarding, Time Anomalies)
- Now covering 9 comprehensive threat categories
- Enhanced coverage for insider threats and APT behavior

**Visual Display Improvements:**
- Color-coded severity indicators with visual badges (HIGH/MED/LOW)
- Smart row highlighting based on threat scores
- Quick-filter buttons for instant severity filtering
- Professional table styling with clear visual hierarchy
- Improved summary statistics dashboard

**Enhanced User Experience:**
- One-click severity filtering for rapid threat triage
- Export respects current filters and sorting
- Better visual feedback for high-priority threats
- Cleaner, more intuitive interface

## Features

### 🎯 Detection Strategies

The dashboard includes **nine comprehensive threat hunting strategies**:

**Beacon Hunter (C2 Detection)**
- Detects command-and-control beaconing behavior by analyzing connection timing patterns
- Identifies rhythmic network traffic indicative of automated callbacks
- Calculates beacon scores based on connection consistency and frequency
- Useful for finding compromised hosts communicating with C2 servers

**Entropy Analyzer (DNS Tunneling)**
- Detects DNS tunneling and Domain Generation Algorithm (DGA) domains
- Calculates Shannon entropy on string fields to identify high-randomness data
- Flags long, high-entropy strings that may indicate data exfiltration
- Helps identify covert channels and encoded communications

**Exfiltration Monitor (Producer/Consumer Ratio)**
- Identifies hosts with unusual upload-to-download traffic ratios
- Detects potential data exfiltration by finding "producer" hosts
- Calculates suspicion scores based on traffic volume and ratio
- Highlights hosts behaving abnormally compared to typical download patterns

**Port Scan Detector (Reconnaissance)**
- Detects port scanning activity indicating network reconnaissance
- Identifies sources scanning multiple ports across multiple targets
- Calculates scan scores based on port diversity and target count
- Essential for detecting the early stages of network attacks

**Brute Force Detector (Authentication Attacks)**
- Identifies credential stuffing and password spraying attacks
- Analyzes authentication logs for high failure rates
- Detects rapid-fire authentication attempts
- Critical for protecting authentication endpoints

**Protocol Tunneling Detector (Covert Channels)**
- Detects unusual protocol usage and covert communication channels
- Identifies high data volumes on non-standard ports
- Flags potential SSH tunneling, DNS tunneling, and protocol encapsulation
- Helps uncover command-and-control over uncommon protocols

**Lateral Movement Detector (Privilege Escalation)** 🆕
- Identifies suspicious lateral movement patterns across the network
- Detects single sources accessing many targets in short time windows
- Tracks speed and breadth of network access
- Critical for catching attackers moving through your infrastructure

**Data Hoarding Detector (Theft Preparation)** 🆕
- Identifies unusual data collection and bulk download patterns
- Detects hosts accessing many data sources or downloading large volumes
- Flags potential data theft preparation before exfiltration
- Helps identify insider threats and compromised accounts collecting sensitive data

**Time-Based Anomaly Detector (Off-Hours Activity)** 🆕
- Identifies suspicious activity outside normal business hours
- Detects weekend and late-night access patterns
- Flags potential unauthorized access and insider threats
- Essential for catching activity that doesn't match normal user behavior

### 🔧 Interactive Controls

**Dynamic Schema Discovery**
- Automatically discovers available tables from the IONIC database
- Caches table list locally for 7 days to improve performance
- Provides schema inspection with support for nested fields
- Intelligent column mapping with dropdown selectors

**Flexible Query Options**
- Configurable row limits (1 to 1,000,000 rows)
- Offset-based pagination for SQL-level data retrieval
- Optional date range filtering with enable/disable toggle
- Automatic query construction with SQL injection protection

**Results Visualization** 🎨 Enhanced!
- **Color-coded severity badges** - Visual HIGH/MED/LOW indicators in results
- **Quick severity filters** - One-click filtering by High (≥75), Medium (50-74), or Low (<50) scores
- **Smart row highlighting** - Automatic color-coding based on threat severity
  - High severity: Light red background (#ffebee)
  - Medium severity: Light orange background (#fff3e0)
  - Low severity: Light green background (#e8f5e9)
- Summary statistics dashboard with severity breakdowns
- Interactive visualizations using Plotly (when available)
- Sortable result tables with column-based ordering
- Paginated result viewing (100 rows per page with Previous/Next navigation)
- Collapsible column explanations for cleaner display
- CSV export functionality respecting current filters and sorting
- Professional table styling with clear visual hierarchy

### 🛡️ Security Features

- SQL injection prevention through identifier sanitization
- Date input validation with regex pattern matching
- Parameterized query construction
- Secure handling of user inputs throughout the interface

### ⚡ Performance Optimizations

- Local caching of table discovery queries (7-day TTL)
- Configurable cache location and expiration
- Efficient pagination of large result sets
- Lazy loading of table schemas

## Getting Started

### Prerequisites

- Jupyter Notebook environment (ALEX or compatible)
- Access to `ionic_scripting_framework` (isf)
- Python packages: `ipywidgets`, `pandas`, `scipy`, `plotly` (optional)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd 221B
```

2. Open the Jupyter notebook:
```bash
jupyter notebook 221B_Notebook.ipynb
```

### Basic Usage

1. **Initialize the Dashboard**
   - Run the notebook cells to load the WatsonDashboard
   - Wait for table list to load (cached after first run)

2. **Select a Strategy**
   - Choose from Beacon, Entropy, or Exfiltration tabs
   - Review the required inputs for your selected strategy

3. **Configure Data Source**
   - Use the table filter to search for your target table
   - Click "Load Table Schema" to discover available columns
   - Map the required fields to your table's columns

4. **Set Query Options**
   - Adjust row limit (default: 10,000)
   - Set offset for SQL-level pagination (default: 0)
   - Optionally enable date filtering and select date range

5. **Run Analysis**
   - Click "Run Analysis" to execute the threat hunt
   - Review column explanations at the top
   - Explore interactive visualizations
   - Navigate through paginated results using Previous/Next buttons

### Example Workflow

```python
from app import WatsonDashboard
from strategies import (
    BeaconStrategy, 
    EntropyStrategy, 
    ExfilStrategy,
    PortScanStrategy,
    BruteForceStrategy,
    TunnelingStrategy,
    LateralMovementStrategy,
    DataHoardingStrategy,
    TimeAnomalyStrategy
)

# Initialize dashboard with all strategies and custom cache settings
dashboard = WatsonDashboard(
    strategies=[
        BeaconStrategy(),
        EntropyStrategy(),
        ExfilStrategy(),
        PortScanStrategy(),
        BruteForceStrategy(),
        TunnelingStrategy(),
        LateralMovementStrategy(),
        DataHoardingStrategy(),
        TimeAnomalyStrategy()
    ],
    cache_dir='.custom_cache',
    cache_days=3
)

# Display the dashboard
dashboard.display()
```

### Using the Enhanced UI Features

**Filtering Results by Severity:**
- After running an analysis, use the quick filter buttons at the top of results
- Click "High (≥75)" to see only critical threats
- Click "Medium (50-74)" for moderate threats
- Click "Low (<50)" for informational findings
- Click "All" to reset and show everything

**Understanding Visual Indicators:**
- **RED rows with HIGH badge** = Critical threats requiring immediate attention (score ≥75)
- **ORANGE rows with MED badge** = Suspicious activity worth investigating (score 50-74)
- **GREEN rows with LOW badge** = Lower priority anomalies (score <50)

**Exporting Filtered Results:**
- Apply any filters and sorting you want
- Click the "📥 Export CSV" button
- The exported file will contain only the filtered and sorted results
- Files are timestamped for easy tracking

## Project Structure

```
221B/
├── app.py              # Main dashboard application and UI logic
├── strategies.py       # Threat hunting strategy implementations
├── 221B_Notebook.ipynb # Jupyter notebook interface
├── .221b_cache/        # Local cache directory (auto-created)
└── README.md          # This file
```

### Key Components

**app.py - WatsonDashboard Class**
- Manages the overall dashboard UI and workflow
- Handles table discovery and caching
- Builds dynamic column mapping interfaces
- Executes queries and displays results
- Implements pagination and filtering controls

**strategies.py - HuntStrategy Classes**
- Abstract base class defining the strategy pattern
- Concrete implementations for each detection method
- Analysis logic separated from UI concerns
- Optional visualization generation
- Column explanation system for analyst education

## Configuration

### Cache Settings

Configure cache behavior when initializing the dashboard:

```python
dashboard = WatsonDashboard(
    strategies=my_strategies,
    cache_dir='.my_cache',    # Custom cache directory
    cache_days=14              # Cache expiration in days
)
```

### Display Options

Result pagination can be adjusted in the `_display_sortable_results` method:

```python
# Default: 100 rows per page
self._display_sortable_results(result_df, rows_per_page=100)
```

## Advanced Features

### Custom Strategies

Create custom threat hunting strategies by extending the `HuntStrategy` base class:

```python
from strategies import HuntStrategy

class CustomStrategy(HuntStrategy):
    def _get_name(self) -> str:
        return "Custom Threat Hunt"
    
    def _get_required_inputs(self) -> list:
        return ['timestamp', 'source_ip']
    
    def analyze(self, df: pd.DataFrame, col_map: dict) -> pd.DataFrame:
        # Your analysis logic here
        return result_df
    
    def get_column_explanations(self) -> dict:
        return {
            'column_name': 'Explanation of what this column means'
        }
```

### Nested Field Support

The dashboard automatically discovers and expands nested fields in structured data types:

- Supports Trino `ROW` types
- Handles multiple levels of nesting (up to 3 levels deep)
- Generates dot-notation paths (e.g., `parent.child.grandchild`)

## Troubleshooting

**Tables not appearing**
- Verify IONIC connection via `ionic_scripting_framework`
- Check cache file at `.221b_cache/available_tables.json`
- Delete cache to force refresh

**Date filtering not working**
- Ensure your strategy includes a 'timestamp' required input
- Verify timestamp column is mapped in Column Mapping section
- Check that dates are selected in both start and end date pickers

**Performance issues with large datasets**
- Reduce the row limit in Query Options
- Use date filtering to narrow the data window
- Consider using SQL-level offset for large result sets

**Cache not updating**
- Delete `.221b_cache/` directory
- Wait 7 days for automatic expiration
- Or adjust `cache_days` parameter

## Contributing

When adding new features or strategies:

1. Follow the existing code structure and patterns
2. Implement proper input sanitization for security
3. Add column explanations for analyst-facing outputs
4. Test with various data sources and edge cases
5. Update this README with new functionality

## Security Considerations

- All SQL identifiers are sanitized using regex validation
- Date inputs are validated before query construction  
- User inputs cannot directly inject SQL code
- Cache files contain no sensitive data (table names only)

## License

[Add license information here]

## Support

For issues or questions:
- Check the Troubleshooting section above
- Review code comments in `app.py` and `strategies.py`
- Consult IONIC/ALEX documentation for connection issues
