# 221B - Interactive Threat Hunting Dashboard

A Jupyter notebook-based threat hunting platform that provides interactive analysis of network security data through pre-built detection strategies.

## Overview

221B is a no-code threat hunting tool designed for security analysts to investigate network traffic and detect malicious behavior patterns. It connects to IONIC data stores via the `ionic_scripting_framework` and provides an intuitive widget-based interface for running various threat detection strategies.

### 🆕 What's New in This Release

**Code Quality & Consolidation:**
- 🔧 **Major code consolidation** - Improved maintainability and reduced duplication
- **Gradient pattern consolidation** - 9+ inline CSS gradients replaced with reusable constants
- **Magic number elimination** - All severity thresholds now use named constants for easier maintenance
- **Enhanced code consistency** - Single source of truth for styling and threshold values
- All improvements maintain 100% backward compatibility with zero breaking changes

**Detection Coverage:**
- 📊 **36 comprehensive threat hunting strategies** covering modern attack vectors
- Including: API Gateway Abuse, Kerberos Attacks, Macro Malware, Network Covert Channels
- Enhanced coverage for API attacks, Active Directory threats, Office document malware, and hidden communications
- Previous additions: Insider Threats, Ransomware Behavior, Zero-Day Exploitation, Cloud Misconfigurations
- Also includes: Supply Chain Attacks, Container Escapes, DNS Exfiltration, Process Injection, LOLBin Abuse, OAuth Abuse
- Plus: privilege escalation, web shells, credential dumping, ransomware indicators, fileless attacks, API abuse, shadow IT
- Foundational strategies: Beacon Detection, Entropy Analysis, Exfiltration, Port Scanning, Brute Force, and more

**Visual Display Improvements:**
- 🆕 **Threat Velocity Gauge** - Real-time monitoring of threat detection rates with trend visualization
- 🆕 **JSON Export** - Export results as JSON for SIEM integration alongside traditional CSV
- Color-coded severity indicators with visual badges (HIGH/MED/LOW)
- Smart row highlighting based on threat scores
- Quick-filter buttons for instant severity filtering
- Professional table styling with clear visual hierarchy
- Improved summary statistics dashboard
- **IP Address Threat Heatmap** - Visualize which IPs generate the most threats across strategies
- **Strategy Effectiveness Insights** - Compare detection rates and severity distributions
- **Three-Row Quick Action Layout** - Better organized controls with 13 total buttons

**Enhanced User Experience:**
- 🆕 **13 Quick Action Buttons** - Now includes Threat Velocity gauge for real-time monitoring
- 🆕 **Regex Search Mode** - Enable advanced pattern matching for powerful data filtering (e.g., `192\.168\..*` or `malware|trojan`)
- 🆕 **Cache Freshness Indicators** - See cache age with visual warnings when data is getting stale
- One-click severity filtering for rapid threat triage
- Dual export formats: CSV for traditional analysis, JSON for automation and SIEM integration
- Better visual feedback for high-priority threats
- Cleaner, more intuitive interface with reorganized quick actions
- Real-time performance tracking with execution time and throughput metrics
- Advanced text search across all result columns for instant filtering
- Interactive timeline analysis with temporal heatmaps
- Smart recommendations that suggest next investigation steps
- Context-aware workflow guidance based on detections
- **Threat Overview Dashboard** - See all strategies at a glance with comprehensive visualizations

**🎯 Advanced Analyst Workflow Features:**
- **Quick Triage Dashboard** - View all high-severity threats across all strategies in one place
- **Cross-Strategy Correlation** - Automatically identify IPs appearing in multiple detection strategies
- **HTML Investigation Reports** - Generate comprehensive, formatted reports for documentation and sharing
- **Threat Prioritization** - Intelligent aggregation and ranking of threats across all analyses
- **IP Threat Heatmap** 🆕 - Bubble chart showing IP distribution across strategies with threat scores
- **Strategy Insights** 🆕 - Stacked bar charts comparing effectiveness and severity breakdowns
- **One-Click Analysis Tools** - Fast access to correlation, triage, and visualization views

## Features

### 🎯 Detection Strategies

The dashboard includes **thirty-six comprehensive threat hunting strategies**:

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

**Geo-Anomaly Detector (Suspicious Locations)** ⚡ NEW
- Identifies connections from unusual or high-risk geographic locations
- Detects impossible travel scenarios (same account from multiple countries rapidly)
- Flags access from sanctioned or high-risk countries (CN, RU, KP, IR, etc.)
- Essential for detecting account compromise and VPN/proxy abuse
- Helps identify state-sponsored attacks and geographic anomalies

**User-Agent Anomaly Detector (Bot & Attack Detection)** ⚡ NEW
- Identifies attack tools and malicious user agents (sqlmap, nmap, nikto, etc.)
- Detects automated bots, scrapers, and scanning activity
- Flags empty or suspiciously short user agent strings
- Analyzes user agent diversity patterns
- Critical for identifying reconnaissance and automated attacks

**Crypto Mining Detector (Cryptojacking)** ⚡ NEW
- Detects unauthorized cryptocurrency mining activity
- Identifies connections to known mining pools and stratum servers
- Flags traffic on common mining ports (3333, 4444, 5555, etc.)
- Analyzes persistent connections patterns typical of mining operations
- Essential for detecting cryptojacking malware and policy violations

**DNS Anomaly Detector (Malware C2 & Exfiltration)** 🆕 LATEST
- Detects suspicious DNS query patterns indicating malware communication
- Identifies Domain Generation Algorithm (DGA) domains with high entropy
- Flags queries to suspicious TLDs (.tk, .ml, .ga, etc.) commonly used by malware
- Analyzes excessive NXDOMAIN (failed lookup) rates suggesting reconnaissance
- Detects potential DNS tunneling through long query strings
- Essential for catching modern malware C2 channels and data exfiltration

**Account Takeover Detector (Credential Theft)** 🆕 LATEST
- Identifies account compromise and credential theft patterns
- Detects rapid IP address switching indicating credential stuffing attacks
- Flags impossible travel scenarios (same account from multiple locations)
- Analyzes authentication failure patterns followed by success from different IPs
- Identifies off-hours access anomalies suggesting unauthorized use
- Critical for detecting stolen credentials and account hijacking

**Data Staging Detector (Exfiltration Preparation)** 🆕 LATEST
- Identifies data collection and preparation activities before exfiltration
- Detects compression and archiving operations on sensitive files
- Flags rapid sequential access to many files (bulk collection patterns)
- Analyzes access to sensitive directories (finance, HR, customer data)
- Identifies large file operations and staging directory usage
- Essential for catching insider threats and APT data theft in preparation phase

**Fileless Malware Detector (LOLBins & Memory Attacks)** 🆕 NEWEST
- Identifies memory-resident attacks and living-off-the-land techniques
- Detects PowerShell abuse, WMI execution, and suspicious script activity
- Flags use of legitimate system tools for malicious purposes (certutil, bitsadmin, regsvr32, etc.)
- Analyzes encoded and obfuscated command-line patterns
- Critical for detecting modern attacks that avoid writing files to disk
- Essential for catching fileless ransomware, reflective DLL injection, and in-memory payloads

**API Abuse Detector (Scraping & Rate Limit Violations)** 🆕 NEWEST
- Identifies excessive API usage, rate limit violations, and token abuse
- Detects automated scraping and credential stuffing via APIs
- Analyzes abnormal API consumption patterns indicating account compromise
- Flags low endpoint diversity with high request volume (scraping behavior)
- Detects token switching and authentication failure patterns
- Critical for protecting APIs from abuse and detecting data theft via legitimate channels

**Shadow IT Detector (Unauthorized Cloud & SaaS)** 🆕 NEWEST
- Identifies employees using personal cloud storage services
- Detects unapproved collaboration tools and file sharing services
- Flags data synchronization to non-corporate accounts (Dropbox, Google Drive, OneDrive)
- Analyzes usage of paste sites and unauthorized file transfer services
- Monitors data upload volumes to unauthorized services
- Critical for data loss prevention, compliance, and preventing exfiltration via approved channels

**Privilege Escalation Detector (Unauthorized Elevation)** ⚡ LATEST
- Identifies suspicious privilege escalation attempts and abuse
- Detects sudo abuse, runas commands, and token manipulation
- Flags use of credential dumping tools (mimikatz, gsecdump, etc.)
- Analyzes administrative tool usage patterns (net.exe, wmic.exe, psexec, etc.)
- Critical for detecting unauthorized privilege gains and insider threats
- Essential for catching lateral movement and account compromise

**Webshell Detection (Backdoor Access)** ⚡ LATEST
- Identifies web shell backdoor patterns in web server traffic
- Detects suspicious file uploads and POST requests to script files
- Analyzes command execution parameters in web requests (cmd, exec, shell, etc.)
- Flags attack tool user agents (curl, wget, sqlmap, metasploit, etc.)
- Critical for detecting persistent web-based access
- Essential for catching web application compromise and backdoor deployment

**Credential Dumping Detector (Memory Scraping)** ⚡ LATEST
- Detects memory scraping and credential theft tool usage
- Identifies LSASS process access and memory dumps
- Flags registry hive exports (SAM, SECURITY, SYSTEM databases)
- Analyzes credential harvesting tools (mimikatz, procdump, pypykatz, etc.)
- Critical for detecting credential theft operations
- Essential for catching pass-the-hash and credential replay attacks

**Ransomware Indicator Detector (Early Warning)** ⚡
- Detects early warning signs of ransomware deployment
- Identifies shadow copy deletion and VSS interference
- Flags backup service disruption and boot configuration tampering
- Analyzes mass file operations and encryption patterns
- Critical for ransomware prevention and early detection
- Essential for catching attacks before encryption begins

**Supply Chain Attack Detector (Package Security)** 🆕 NEW
- Detects compromised packages and malicious dependencies
- Identifies typosquatting attempts targeting popular packages
- Flags suspicious registry sources and automated mass downloads
- Analyzes package naming patterns and installation behaviors
- Critical for detecting SolarWinds-style supply chain compromises
- Essential for securing software development pipelines

**Container Escape Detector (Cloud Security)** 🆕 NEW
- Detects container breakout and privilege escalation attempts
- Identifies dangerous capability abuse (CAP_SYS_ADMIN, etc.)
- Flags host filesystem access and Docker socket manipulation
- Analyzes kernel module loading and namespace manipulation
- Critical for securing containerized and Kubernetes environments
- Essential for preventing container-to-host compromises

**DNS Exfiltration Detector (Covert Channels)** 🆕 NEW
- Detects DNS-based data exfiltration beyond standard tunneling
- Identifies base64/hex encoding in subdomain patterns
- Flags TXT record abuse and abnormally large response sizes
- Analyzes query burst patterns and subdomain length consistency
- Critical for catching covert data theft via DNS queries
- Complements DNS Anomaly strategy with exfiltration focus

**Process Injection Detector (Memory Attacks)** 🆕 NEW
- Detects process hollowing, DLL injection, and code injection
- Identifies suspicious API calls (CreateRemoteThread, WriteProcessMemory)
- Flags injection into system processes (lsass.exe, svchost.exe)
- Analyzes cross-process memory manipulation patterns
- Critical for detecting advanced malware and post-exploitation
- Essential for catching fileless malware and in-memory attacks

**Living-off-the-Land Detector (LOLBin Abuse)** 🆕 NEW
- Detects abuse of legitimate system tools for malicious purposes
- Identifies certutil, bitsadmin, regsvr32, and mshta abuse
- Flags download cradles and command obfuscation techniques
- Analyzes proxy execution and evasion patterns
- Critical for catching attackers using built-in Windows tools
- Goes beyond basic fileless detection with advanced LOLBin patterns

**OAuth Abuse Detector (API Security)** 🆕 NEW
- Detects OAuth token theft and refresh token abuse
- Identifies token replay attacks across multiple IP addresses
- Flags excessive refresh token requests and dangerous scopes
- Analyzes authorization code interception patterns
- Critical for securing modern API authentication flows
- Essential for protecting cloud and SaaS environments

**Insider Threat Detector (Behavioral Anomalies)** 🔥 LATEST
- Monitors unusual data access patterns and behavioral changes
- Detects after-hours access combined with bulk downloads
- Identifies excessive resource access and sensitive data collection
- Flags automated access patterns and credential sharing
- Analyzes off-hours activity ratios and multi-IP usage
- Critical for detecting malicious insiders and compromised accounts
- Essential for data loss prevention and early threat detection

**Ransomware Behavior Detector (Real-Time Protection)** 🔥 LATEST
- Detects real-time ransomware-like file operations
- Monitors mass file operations and encryption patterns
- Identifies shadow copy deletion and backup tampering
- Flags ransom note creation and suspicious extensions
- Analyzes rapid file modifications across systems
- Critical for stopping ransomware before encryption completes
- Provides early warning for containment and response

**Zero-Day Exploit Indicator (Advanced Threats)** 🔥 LATEST
- Identifies potential zero-day exploitation attempts
- Detects exploitation framework signatures (Metasploit, Cobalt Strike)
- Analyzes shellcode patterns and protocol violations
- Flags high-entropy payloads and abnormal packet structures
- Monitors rapid retry patterns indicating exploit attempts
- Critical for detecting novel attacks without signatures
- Essential for protecting against unknown vulnerabilities

**Cloud Misconfiguration Detector (Infrastructure Security)** 🔥 NEW
- Detects cloud infrastructure security misconfigurations
- Identifies public storage buckets and overly permissive IAM policies
- Flags unencrypted storage and missing MFA on privileged accounts
- Analyzes open security groups and exposed credentials
- Monitors for default passwords and disabled logging
- Critical for cloud security posture management
- Essential for preventing data breaches via misconfiguration

**API Gateway Abuse Detector (Application Layer Attacks)** 🔥 NEW
- Detects API gateway attacks and abuse patterns
- Identifies GraphQL query complexity abuse and flooding
- Monitors REST API enumeration attempts
- Detects rate limit bypass attempts
- Flags potential timing attacks via response time analysis
- Identifies data scraping and excessive API calls
- Critical for protecting API infrastructure from abuse

**Kerberos Attack Detector (Active Directory Threats)** 🔥 NEW
- Identifies Kerberos-based attack patterns
- Detects Kerberoasting via weak encryption types (RC4-HMAC)
- Flags AS-REP Roasting attempts (pre-auth disabled accounts)
- Monitors for Golden/Silver ticket usage patterns
- Identifies Pass-the-Ticket lateral movement
- Tracks excessive service ticket requests
- Essential for protecting Active Directory environments

**Macro Malware Detector (Document-Based Threats)** 🔥 NEW
- Detects malicious Office macros and VBA execution
- Identifies AutoOpen/AutoExec macro patterns
- Flags suspicious process spawning from Office apps
- Monitors for PowerShell, CMD, WScript execution
- Detects encoded commands and download capabilities
- Analyzes obfuscated VBA code patterns
- Critical for preventing document-based malware infections

**Network Covert Channel Detector (Hidden Communications)** 🔥 NEW
- Identifies covert communication channels in network traffic
- Detects ICMP tunneling via abnormal packet sizes
- Flags timing channels with regular interval patterns
- Monitors uncommon protocol usage (GRE, IPIP, L2TP)
- Identifies steganography via consistent packet sizes
- Detects micro-packet streams for data exfiltration
- Essential for finding hidden command and control channels

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
    RansomwareIndicatorStrategy,
    SupplyChainAttackStrategy,
    ContainerEscapeStrategy,
    DNSExfiltrationStrategy,
    ProcessInjectionStrategy,
    LiveOffLandStrategy,
    OAuthAbuseStrategy,
    InsiderThreatStrategy,
    RansomwareBehaviorStrategy,
    ZeroDayExploitStrategy,
    CloudMisconfigStrategy
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
        TimeAnomalyStrategy(),
        GeoAnomalyStrategy(),
        UserAgentAnomalyStrategy(),
        CryptoMiningStrategy(),
        DNSAnomalyStrategy(),
        AccountTakeoverStrategy(),
        DataStagingStrategy(),
        FilelessMalwareStrategy(),
        APIAbuseStrategy(),
        ShadowITStrategy(),
        PrivilegeEscalationStrategy(),
        WebshellDetectionStrategy(),
        CredentialDumpingStrategy(),
        RansomwareIndicatorStrategy(),
        SupplyChainAttackStrategy(),
        ContainerEscapeStrategy(),
        DNSExfiltrationStrategy(),
        ProcessInjectionStrategy(),
        LiveOffLandStrategy(),
        OAuthAbuseStrategy(),
        InsiderThreatStrategy(),
        RansomwareBehaviorStrategy(),
        ZeroDayExploitStrategy(),
        CloudMisconfigStrategy(),
        APIGatewayAbuseStrategy(),
        KerberosAttackStrategy(),
        MacroMalwareStrategy(),
        NetworkCovertChannelStrategy()
    ],
    cache_dir='.custom_cache',
    cache_days=3
)

# Display the dashboard
dashboard.display()
```

### Using the Enhanced UI Features

**Quick Action Buttons (at the top of the dashboard):**

1. **🚨 Quick Triage** - Instant view of all high-severity threats
   - Shows all findings with scores ≥75 across ALL strategies
   - Perfect for rapid threat assessment and prioritization
   - Displays threat counts by strategy and unique source IPs
   - Export triage results to CSV for immediate action

2. **🔗 Correlations** - Find threats across multiple strategies
   - Automatically identifies IPs appearing in multiple detection strategies
   - Ranks threats by number of strategies that flagged them
   - Shows aggregated threat scores and detection categories
   - Critical for identifying sophisticated, multi-stage attacks

3. **📄 Generate Report** - Create comprehensive HTML investigation report
   - Professional formatted report with all findings
   - Includes executive summary with key statistics
   - Color-coded findings by severity level
   - Ready for documentation, sharing with team, or management reporting

4. **💾 Export All** - Batch export all strategy results
   - Exports all analyzed strategy results to separate CSV files
   - Includes summary statistics with high-severity counts
   - Timestamped filenames for easy tracking
   - Perfect for archiving and downstream analysis

5. **📊 Metrics Dashboard** - Comprehensive threat intelligence view
   - Real-time aggregated statistics across all strategies
   - Strategy effectiveness comparison charts
   - Score distribution visualizations
   - Detection volume analysis

6. **⚡ Performance** - Strategy execution performance statistics ✨ NEW
   - View execution time for each strategy
   - Analyze throughput rates (rows/second)
   - Compare detection efficiency across strategies
   - Identify fastest strategies for real-time analysis
   - Visual performance charts with Plotly

7. **📅 Timeline** - Temporal threat activity analysis ✨ NEW
   - Interactive heatmaps showing when threats occurred
   - Hourly and daily threat activity patterns
   - Detection timeline by strategy and severity
   - Identify time-based attack patterns
   - Perfect for understanding attack progression

8. **🎯 Recommendations** - Smart next-step suggestions ✨ NEW
   - AI-powered recommendations based on current findings
   - Context-aware strategy suggestions
   - Attack chain analysis and follow-up actions
   - Priority-based recommendations (CRITICAL, HIGH, MEDIUM, LOW)
   - Helps analysts stay ahead of attackers

9. **🗺️ IP Heatmap** - IP address threat visualization ✨ NEW
   - Bubble chart showing which IPs generate the most threats
   - Visualize threat distribution across strategies
   - Interactive tooltips with detailed IP information
   - Perfect for identifying prolific attackers

10. **🎓 Strategy Insights** - Strategy effectiveness comparison ✨ NEW
    - Stacked bar charts comparing detection rates
    - Severity distribution breakdown per strategy
    - Identify most productive detection methods
    - Optimize your threat hunting workflow

11. **📊 Threat Overview Dashboard** 🔥 NEW
    - Comprehensive view of ALL strategies at a glance
    - Overall threat landscape statistics with risk assessment
    - Strategy-by-strategy breakdown with severity counts
    - Multiple interactive visualizations:
      - Stacked bar chart of severity distribution
      - Pie chart of overall severity breakdown
      - Scatter plot of average score vs detection volume
    - Identifies top 5 most concerning strategies
    - Critical/high/medium/low threat counts
    - Unique source IP tracking across all strategies
    - Perfect for executive briefings and daily threat reviews

12. **⚡ Threat Velocity** 🔥 NEW
    - Real-time threat detection velocity metrics
    - Threats per hour and per day calculations
    - Interactive trend visualization over time
    - Shows average detection rate with baseline
    - Identifies top 5 most active detection strategies
    - Perfect for understanding attack intensity and patterns
    - Essential for capacity planning and resource allocation

13. **❓ Tips** - Usage tips and best practices
    - Step-by-step usage guide
    - Power user features overview
    - Investigation strategy recommendations
    - Performance optimization tips

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

**Advanced Search Features:**
- **Plain Text Search**: Enter any text to search across all columns (case-insensitive)
- **Regex Search**: Enable "Regex Mode" checkbox to use regular expressions
  - Example: `192\.168\..*` to find all 192.168.x.x IPs
  - Example: `malware|trojan|virus` to find rows containing any of these terms
  - Example: `\d{3}-\d{3}-\d{4}` to find phone number patterns
- Search is applied across ALL columns simultaneously for maximum flexibility
- Invalid regex patterns automatically fall back to plain text search

**Exporting Filtered Results:**
- Apply any filters and sorting you want
- Click the "📥 Export CSV" button to export as CSV (traditional analysis)
- Click the "📦 Export JSON" button to export as JSON (SIEM integration, APIs)
- The exported file will contain only the filtered and sorted results
- JSON format includes ISO-formatted timestamps perfect for programmatic processing

**Cache Management:**
- Table list is automatically cached for 7 days to improve performance
- Cache age is shown when loading tables with freshness indicators:
  - ✅ Fresh - Cache is recent and reliable
  - ⚠️ Consider refreshing soon - Cache is approaching expiry (>80% of cache_days)
- Delete `.221b_cache/` directory to force refresh
- Or adjust `cache_days` parameter when initializing dashboard
- Files are timestamped for easy tracking

### Analyst Workflow Best Practices

**For Rapid Incident Response:**
1. Run multiple threat detection strategies on your data
2. Click **Quick Triage** to see all critical threats immediately
3. Use **Correlations** to identify IPs with multiple suspicious behaviors
4. Investigate correlated threats first - they're most likely to be real attacks
5. Generate a **Report** for documentation and team communication

**For Comprehensive Threat Hunting:**
1. Select a strategy tab and configure your data source
2. Run the analysis and review the detailed results
3. Use the severity filters to focus on high-priority findings
4. Export individual strategy results as needed
5. After running multiple strategies, use correlation analysis to find patterns
6. Generate final HTML report for record-keeping

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

## Project Statistics

**Current Release:**
- **36 comprehensive threat hunting strategies** covering modern attack vectors
- **114 unit tests** with 100% pass rate
- **13,937 lines of code** across core modules
- **13 quick action buttons** for one-click analysis including Threat Velocity and Overview
- **Multiple export formats** (CSV, JSON) for flexible integration
- **Zero security vulnerabilities** detected by CodeQL analysis

**Code Distribution:**
- `strategies.py`: 6,712 lines - Pure threat detection logic
- `app.py`: 3,633 lines - Interactive UI and dashboard (consolidated)
- `test_strategies.py`: 2,766 lines - Comprehensive test suite
- `README.md`: 826 lines - Complete documentation

**Strategy Coverage:**
- Network-based attacks: 9 strategies (C2, DNS, Port Scans, Tunneling, Exfiltration, Zero-Day, etc.)
- Authentication attacks: 4 strategies (Brute Force, Account Takeover, OAuth Abuse, Credential Dumping)
- Advanced persistent threats: 7 strategies (Lateral Movement, Data Staging, Fileless, Process Injection, Insider Threat, etc.)
- Infrastructure threats: 6 strategies (Container Escape, Crypto Mining, Webshells, Privilege Escalation, LOLBins, Cloud Misconfig)
- Anomaly detection: 5 strategies (Geo, Time, User-Agent, API Abuse, Shadow IT)
- Ransomware detection: 2 strategies (Ransomware Indicators, Real-time Ransomware Behavior)

## License

[Add license information here]

## Support

For issues or questions:
- Check the Troubleshooting section above
- Review code comments in `app.py` and `strategies.py`
- Consult IONIC/ALEX documentation for connection issues
