# 221B - ASOM-Aligned Threat Hunting Dashboard

An interactive, ASOM-based threat hunting platform that provides atomic, rule-based detection strategies mapped to MITRE ATT&CK techniques.

## Overview

221B is a no-code threat hunting tool designed for security analysts to investigate network security data through pre-built detection strategies aligned with the **Actions for Security Operations Monitoring (ASOM)** framework. It connects to IONIC data stores via the `ionic_scripting_framework` and provides an intuitive widget-based interface.

### 🆕 ASOM-Aligned Architecture

**Complete Rebuild - Simple, Atomic, Actionable:**
- 🆕 **15 Detection Strategies** - One per MITRE ATT&CK technique (down from 36)
- 🆕 **23 ASOM Actions** - Rule-based detections from ASOM framework  
- 🆕 **ASOM Browser** - New UI to browse strategies by action and technique
- 🆕 **Simple & Atomic** - Focus on rule-based indicators, minimal ML
- 🆕 **Full MITRE Coverage** - 7 tactics, 15 techniques from ATT&CK framework
- 🆕 **82% Code Reduction** - Cleaner, more maintainable codebase

## Features

### 🎯 ASOM-Aligned Detection Strategies

The dashboard includes **15 comprehensive ASOM-aligned strategies** mapped to MITRE ATT&CK:

#### Initial Access (3 strategies)
- **Valid Accounts Detection** (T1078) - 5 detection actions
  - Detects credential compromise and account misuse
  - Monitors login anomalies, third-party partner abuse, service account misuse
  - Flags privileged group modifications and suspicious command execution
  
- **Replication Through Removable Media Detection** (T1091) - 2 actions
  - Identifies malware propagation via USB and external drives
  - Correlates removable media insertion with suspicious file operations
  
- **External Remote Services Detection** (T1133) - 2 actions
  - Monitors VPN, RDP, and remote access for suspicious activity
  - Correlates remote logins with threat intelligence feeds
  - Detects abnormal session durations and access patterns

- **Exploit Public-Facing Application Detection** (T1190) - 1 action
  - Identifies web exploitation attempts (SQL injection, RCE, Log4j, etc.)
  - Correlates HTTP attacks with process spawning on web servers

#### Execution (7 strategies)
- **Scheduled Task-Job Detection** (T1053) - 3 actions
  - Detects malicious scheduled task creation and modification
  - Identifies privilege escalation via scheduled tasks
  - Monitors for unauthorized task creation by non-privileged users
  
- **PowerShell Detection** (T1059.001) - 1 action
  - Identifies suspicious PowerShell execution patterns
  - Monitors System.Management.Automation.dll loading
  
- **Windows Command Shell Detection** (T1059.003) - 1 action
  - Detects malicious batch file creation and execution
  - Correlates file creation with rapid execution (automated scripts)
  
- **Unix Shell Detection** (T1059.004) - 1 action
  - Identifies web servers and other services spawning shells
  - Detects command injection and remote code execution
  
- **Network Device CLI Detection** (T1059.008) - 1 action
  - Monitors unauthorized network device configuration changes
  - Detects suspicious CLI command execution
  
- **Cloud API Detection** (T1059.009) - 1 action
  - Identifies suspicious cloud CLI tool usage (AWS, Azure, GCP)
  - Monitors for cloud infrastructure enumeration
  
- **Container Administration Command Detection** (T1609) - 1 action
  - Detects suspicious Docker/Kubernetes administration commands
  - Identifies container escape attempts

#### Persistence (4 strategies)
- **Scheduled Task-Job Detection** (T1053) - Also covers persistence
- **Valid Accounts Detection** (T1078) - Also covers persistence  
- **External Remote Services Detection** (T1133) - Also covers persistence
- **Web Shell Detection** (T1505.003) - 1 action
  - Identifies web shell deployment in web directories
  - Detects suspicious script file creation by web server processes

#### Privilege Escalation (3 strategies)
- **Scheduled Task-Job Detection** (T1053) - Also covers privilege escalation
- **Valid Accounts Detection** (T1078) - Also covers privilege escalation

#### Defense Evasion (1 strategy)
- **Valid Accounts Detection** (T1078) - Also covers defense evasion

#### Lateral Movement (1 strategy)
- **Replication Through Removable Media Detection** (T1091) - Also covers lateral movement

#### Command And Control (3 strategies)
- **Web Protocols Detection** (T1071.001) - 1 action
  - Correlates network traffic with threat intelligence feeds
  - Identifies C2 communication over HTTP/HTTPS
  
- **DNS Detection** (T1071.004) - 1 action
  - Identifies suspicious processes initiating DNS queries
  - Detects DNS tunneling and DGA domains
  
- **Non-Application Layer Protocol Detection** (T1095) - 1 action
  - Detects C2 communication over non-standard protocols (UDP, ICMP, etc.)
  - Correlates with threat intelligence for known C2 infrastructure

### 📋 ASOM Browser

**New Feature: Browse Strategies by Action**
- Interactive UI to explore ASOM action to strategy mappings
- Group strategies by MITRE ATT&CK tactic
- View detection actions for each strategy
- See coverage statistics (techniques, actions, tactics)
- Understand what each strategy detects

Access via the **📋 ASOM** button in the quick actions toolbar.

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
- **Color-coded severity badges** - Visual HIGH/MED/LOW indicators
- **Quick severity filters** - One-click filtering by threat level
- **Smart row highlighting** - Automatic color-coding based on severity
- Summary statistics dashboard with severity breakdowns
- Interactive visualizations using Plotly (when available)
- Sortable result tables with column-based ordering
- Paginated result viewing (100 rows per page)
- CSV and JSON export functionality

### 🎯 Advanced Analyst Workflow Features

- **Quick Triage Dashboard** - View all high-severity threats in one place
- **Cross-Strategy Correlation** - Identify IPs appearing in multiple strategies
- **HTML Investigation Reports** - Generate comprehensive reports
- **Threat Prioritization** - Intelligent threat aggregation and ranking
- **IP Threat Heatmap** - Visualize IP distribution across strategies
- **Strategy Insights** - Compare effectiveness and severity breakdowns
- **Performance Metrics** - Track execution time and throughput
- **Temporal Analysis** - Interactive timeline heatmaps

## Getting Started

### Prerequisites

- Jupyter Notebook environment (ALEX or compatible)
- Access to `ionic_scripting_framework` (isf)
- Python packages: `ipywidgets`, `pandas`, `plotly` (optional)

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

2. **Explore ASOM Mappings**
   - Click the **📋 ASOM** button to browse strategy mappings
   - See which strategies cover which MITRE ATT&CK techniques
   - Understand the detection actions each strategy implements

3. **Select a Strategy**
   - Choose from 15 ASOM-aligned strategy tabs
   - Review the MITRE ATT&CK technique and tactics covered
   - See the required inputs for your selected strategy

4. **Configure Data Source**
   - Use the table filter to search for your target table
   - Click "Load Table Schema" to discover available columns
   - Map the required fields to your table's columns

5. **Set Query Options**
   - Adjust row limit (default: 10,000)
   - Set offset for SQL-level pagination (default: 0)
   - Optionally enable date filtering and select date range

6. **Run Analysis**
   - Click "Run Analysis" to execute the threat hunt
   - Review column explanations at the top
   - Explore results with sorting and filtering
   - Use severity filters (High ≥75, Medium 50-74, Low <50)

### Example Workflow

```python
from app import WatsonDashboard
from strategies import (
    ScheduledTaskJobStrategy,
    PowerShellStrategy,
    WindowsCommandShellStrategy,
    UnixShellStrategy,
    NetworkDeviceCLIStrategy,
    CloudAPIStrategy,
    WebProtocolsStrategy,
    DNSStrategy,
    ValidAccountsStrategy,
    ReplicationThroughRemovableMediaStrategy,
    NonApplicationLayerProtocolStrategy,
    ExternalRemoteServicesStrategy,
    ExploitPublicFacingApplicationStrategy,
    WebShellStrategy,
    ContainerAdministrationCommandStrategy
)

# Initialize dashboard with all ASOM-aligned strategies
dashboard = WatsonDashboard(
    strategies=[
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
        ContainerAdministrationCommandStrategy()
    ],
    cache_dir='.221b_cache',
    cache_days=7
)

# Display the dashboard
dashboard.display()
```

## Project Structure

```
221B/
├── app.py                           # Main dashboard application and UI logic
├── strategies.py                    # ASOM-aligned threat hunting strategies
├── 221B_Notebook.ipynb             # Jupyter notebook interface
├── asom_d3fend_merged_20251208_183213.xlsx  # ASOM framework data
├── .221b_cache/                    # Local cache directory (auto-created)
├── README.md                       # This file
└── strategies_old.py               # Backup of previous implementation
```

## Architecture

### ASOM-Aligned Design

**Key Principles:**
1. **Atomic Strategies** - One strategy per MITRE ATT&CK technique
2. **Rule-Based Focus** - Simple, actionable detections over complex ML
3. **ASOM Framework** - Each strategy maps to specific ASOM actions
4. **MITRE Mapping** - Full traceability to ATT&CK techniques and tactics

**Strategy Structure:**
- Each strategy extends `HuntStrategy` base class
- Contains technique ID, tactics, and ASOM actions metadata
- Implements `analyze()` method for detection logic
- Returns DataFrame with threat scores and explanations

### ASOM Browser Integration

The ASOM Browser provides transparency into strategy coverage:
- Shows all 15 strategies grouped by MITRE tactic
- Displays ASOM actions each strategy implements
- Provides coverage statistics (techniques, actions, tactics)
- Helps analysts understand detection capabilities

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

## Advanced Features

### Custom Strategies

Create custom ASOM-aligned strategies by extending the `HuntStrategy` base class:

```python
from strategies import HuntStrategy

class CustomStrategy(HuntStrategy):
    def _get_name(self) -> str:
        return "Custom Detection"
    
    def _get_technique_id(self) -> str:
        return "T1234"
    
    def _get_tactics(self) -> list:
        return ['Initial Access']
    
    def _get_asom_actions(self) -> list:
        return ['Action description 1', 'Action description 2']
    
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

## Project Statistics

**Current Release:**
- **15 ASOM-aligned strategies** covering modern attack vectors
- **23 rule-based detection actions** from ASOM framework
- **15 MITRE ATT&CK techniques** across 7 tactics
- **1,652 lines** of strategy code (82% reduction from 8,982)
- **Zero ML complexity** - pure rule-based detections
- **ASOM Browser UI** - new feature for exploring mappings

**Coverage:**
- Initial Access: 4 strategies
- Execution: 7 strategies  
- Persistence: 4 strategies
- Privilege Escalation: 3 strategies
- Defense Evasion: 1 strategy
- Lateral Movement: 1 strategy
- Command And Control: 3 strategies

## Contributing

When adding new strategies:

1. Follow ASOM framework alignment
2. Map to specific MITRE ATT&CK technique
3. Keep detections atomic and rule-based
4. Add ASOM action descriptions
5. Update ASOM Browser if needed
6. Test with various data sources
7. Update this README with new functionality

## Security Considerations

- All SQL identifiers are sanitized using regex validation
- Date inputs are validated before query construction  
- User inputs cannot directly inject SQL code
- Cache files contain no sensitive data (table names only)

## License

[Add license information here]

## Support

For issues or questions:
- Check the Troubleshooting section in documentation
- Review code comments in `app.py` and `strategies.py`
- Use the ASOM Browser to understand strategy coverage
- Consult IONIC/ALEX documentation for connection issues
