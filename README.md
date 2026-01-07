# 221B - ASOM-Aligned Threat Hunting Platform

An intelligence-driven threat hunting platform aligned with the **Analytic Scheme of Maneuver (ASOM)** framework. Answers Commander's Critical Information Requirements (CCIRs) through progressively sophisticated detection strategies.

## Overview

221B is a Jupyter notebook-based threat hunting tool that implements ASOM-aligned detection strategies. Each strategy answers a specific CCIR using up to three sophistication levels:

1. **Level 1 (Rule-Based)**: Watchlists, correlation rules, pattern matching
2. **Level 2 (Statistical)**: Baseline analysis and anomaly detection
3. **Level 3 (Machine Learning)**: Supervised and unsupervised ML models

## ASOM Framework

The platform implements **23 ASOM strategies** covering:

- **Initial Access (TA0001)**: 5 CCIRs
- **Execution (TA0002)**: 7 CCIRs  
- **Persistence (TA0003)**: 4 CCIRs
- **Privilege Escalation (TA0004)**: 2 CCIRs
- **Defense Evasion (TA0005)**: 1 CCIR
- **Lateral Movement (TA0008)**: 1 CCIR
- **Command & Control (TA0011)**: 3 CCIRs

See [ASOM_STRATEGY_PLAN.md](ASOM_STRATEGY_PLAN.md) for complete strategy details.

## Currently Implemented Strategies

### CCIR 1: Compromised Credentials Detector

**Question**: Has an adversary gained initial access using compromised credentials?

**Sophistication Levels**:
- **Level 1**: Detects brute force (20+ failed attempts → success), post-login reconnaissance commands
- **Level 2**: Statistical baseline of login patterns (hours, location, data volume), detects anomalies
- **Level 3**: Machine learning (Isolation Forest) on session characteristics with confidence scores

**Data Sources**: Windows Event IDs 4624/4625, Zeek conn.log, Sysmon Events 1/3

**Example Detection**:
```
Threat Score: 100
Severity: HIGH
Detection Level: 1
Explanation: Successful login after 25 failed attempts in 2.2 minutes - Potential credential stuffing
```

### CCIR 22: DNS C2 Detector

**Question**: Is an adversary using the Domain Name System (DNS) protocol for command and control communications?

**Implementation**: 2 Indicators with 3 Sophistication Levels Each (6 Actions Total)

#### Indicator 1: Process-Based Detection
- **Level 1**: Watchlist of suspicious processes (cmd.exe, powershell.exe, etc.) making DNS queries
  - Alerts when suspicious processes spawn from Office apps, browsers, or PDF readers
  - High threat scores (90+) for Office document spawning PowerShell DNS queries
- **Level 2**: Statistical baseline of DNS behavior per process
  - Tracks hourly query volume, query entropy, unique domains ratio, query types
  - Flags processes deviating > 3 standard deviations from baseline
- **Level 3**: Isolation Forest ML on process activity
  - Features: command line entropy, parent process, DNS metrics in first 60 seconds
  - Identifies anomalous process-DNS behavior patterns

#### Indicator 2: Query-Based Detection
- **Level 1**: Threat intelligence correlation
  - Pattern matching for DGA domains, free TLDs (.tk, .ml, .ga, .cf, .gq)
  - Long numeric strings and high-entropy domain names
- **Level 2**: Statistical baseline of query characteristics
  - Risk scoring: excessive subdomains (>98th %), high FQDN entropy (>98th %), TXT/NULL queries
  - Aggregates per host over 5-minute windows
  - Flags high-volume query bursts (>50 queries/5min)
- **Level 3**: Machine learning classification
  - Features: query length, subdomain labels, Shannon entropy, numeric/alpha ratio, query type, TTL
  - Isolation Forest for unsupervised anomaly detection
  - Plain English explanations of detection factors

**Data Sources**: Sysmon Event IDs 22/1, Windows Event ID 4688, Zeek dns.log, Zeek conn.log, Threat Intelligence Feeds

**Example Detections**:
```
Indicator 1, Level 1:
Threat Score: 90
Severity: HIGH
Explanation: Suspicious process 'powershell.exe' initiated DNS query spawned by 'winword.exe'

Indicator 2, Level 2:
Threat Score: 75
Severity: HIGH
Explanation: DNS query characteristics anomaly: 15 queries with excessive subdomains; 12 TXT/NULL queries; High query volume: 60 queries in 5 minutes
```

## Architecture

### Multi-Table Correlation Framework

Strategies can correlate data across multiple sources:

```python
from strategies import DataCorrelator

correlator = DataCorrelator()

# Temporal correlation within 2-minute window
correlated = correlator.temporal_join(
    windows_events, zeek_logs,
    'timestamp', 'ts',
    join_keys=['source_ip'],
    window_seconds=120
)
```

### Multiprocessing Support

Built-in multiprocessing for performance:

```python
# Automatically uses available CPU cores
# Processes data chunks in parallel
result = strategy.analyze(large_df, col_map)
```

### Machine Learning Integration

Level 3 strategies use scikit-learn with plain English explanations:

```python
# ML columns added automatically when triggered
ml_anomaly_score: 87.5  # 0-100 scale
ml_confidence: 🔴 HIGH CONFIDENCE
ml_explanation: Key factors: High login_hour, High session_bytes, Moderate command_entropy
```

## Getting Started

### Prerequisites

```bash
pip install pandas numpy scipy scikit-learn ipywidgets
```

### Installation

```bash
git clone <repository-url>
cd 221B
jupyter notebook 221B_Notebook.ipynb
```

### Basic Usage

```python
from app import WatsonDashboard
from strategies import get_all_strategies

# Load all ASOM strategies
strategies = get_all_strategies()

# Create dashboard
dashboard = WatsonDashboard(strategies)
dashboard.display()
```

### Running a Strategy

1. Select strategy tab (e.g., "Compromised Credentials Detector")
2. Choose data source table
3. Map required columns to your table's schema
4. Configure date range and row limits
5. Click "Run Analysis"
6. Review results with severity filtering and ML insights

## Output Format

All strategies return consistent output:

| Column | Description |
|--------|-------------|
| `timestamp` | Event timestamp |
| `source_ip` | Source IP address |
| `username` | Account name (when applicable) |
| `threat_score` | Numeric score 0-100 (higher = more suspicious) |
| `severity` | HIGH (≥75), MED (50-74), LOW (<50) |
| `detection_level` | 1 (rule-based), 2 (statistical), 3 (ML) |
| `explanation` | Human-readable detection reason |
| `ml_anomaly_score` | ML score (Level 3 only) |
| `ml_confidence` | HIGH/MEDIUM/LOW (Level 3 only) |
| `ml_explanation` | Feature importance (Level 3 only) |

## Testing

Comprehensive test suite with 22 tests covering all sophistication levels:

```bash
python -m unittest test_asom_strategies -v
```

**Test Coverage**:
- Strategy metadata validation
- Level 1 rule-based detection
- Level 2 statistical baselines
- Level 3 ML anomaly detection
- Empty data handling
- Severity labeling
- Multi-table correlation
- Both indicators (process-based and query-based)

**Test Results**:
```
Ran 22 tests in 1.022s
OK
```

**All tests pass** ✅

## Development Roadmap

Current implementation: **2 of 23 strategies** (CCIRs 1 and 22 complete)

### Completed Strategies ✅
1. **CCIR 1**: Compromised Credentials Detection
2. **CCIR 22**: DNS C2 Detection

### Next Strategies to Implement

1. **CCIR 5**: Public-Facing Application Exploit Detection
2. **CCIR 7**: PowerShell Execution Detection
3. **CCIR 16**: Web Shell Persistence Detection
4. **CCIR 21**: HTTP/HTTPS C2 Detection

Each new strategy follows the template established by CompromisedCredentialsStrategy and DNSC2Strategy.

## Project Structure

```
221B/
├── strategies.py           # ASOM-aligned detection strategies
├── app.py                  # Dashboard UI and IONIC integration
├── test_asom_strategies.py # Comprehensive test suite
├── ASOM_STRATEGY_PLAN.md   # Complete implementation plan
├── 221B_Notebook.ipynb     # Jupyter interface
└── README.md               # This file
```

## Key Features

### Intelligence-Driven
- Aligned with military ASOM framework
- Answers specific CCIRs
- Progressive sophistication levels

### Multi-Source Correlation
- Joins Windows Events, Sysmon, Zeek logs
- Temporal correlation within configurable windows
- Entity-based aggregation (IP, user, host)

### Performance Optimized
- Multiprocessing for large datasets
- Efficient pandas operations
- Configurable chunk sizes

### Analyst-Friendly
- Plain English explanations
- Confidence levels for prioritization
- Visual severity indicators
- Column-by-column documentation

### Machine Learning
- Isolation Forest for anomaly detection
- Random Forest for classification
- StandardScaler for feature normalization
- Feature importance explanations

## Data Source Requirements

### Windows Event Logs
- Event ID 4624 (Successful Logon)
- Event ID 4625 (Failed Logon)
- Event ID 4688 (Process Creation)
- Event ID 4698/4702 (Scheduled Tasks)

### Sysmon Logs
- Event ID 1 (Process Creation)
- Event ID 3 (Network Connection)
- Event ID 11 (File Creation)
- Event ID 22 (DNS Query)

### Zeek Logs
- conn.log (Network Connections)
- dns.log (DNS Queries)
- http.log (HTTP Requests)
- ssh.log, rdp.log (Remote Access)

### Cloud Logs (Future)
- AWS CloudTrail
- Azure Activity Logs
- Google Cloud Audit Logs

## Security

- SQL injection prevention via identifier sanitization
- No credentials stored in code
- Parameterized query construction
- Input validation on all user inputs

## Contributing

When implementing new ASOM strategies:

1. Follow CompromisedCredentialsStrategy or DNSC2Strategy templates
2. Implement all 3 sophistication levels where applicable
3. Support multiple indicators if specified in ASOM
4. Add comprehensive tests (minimum 9-11 test cases per strategy)
5. Update ASOM_STRATEGY_PLAN.md with implementation status
6. Document column explanations
7. Ensure ML triggers with proper sample sizes (50+)
8. Update README.md with strategy details

## Performance Statistics

- **Strategies**: 2 of 23 implemented (8.7%)
- **ASOM Actions**: 9 total (3 for CCIR 1, 6 for CCIR 22)
- **Test Coverage**: 22 tests, 100% pass rate
- **Lines of Code**: ~1,700 (strategies.py)
- **ML Support**: Isolation Forest, Random Forest, One-Class SVM ready
- **Multiprocessing**: Automatic parallelization

## Acknowledgments

- ASOM framework alignment
- MITRE ATT&CK tactics mapping
- Military CCIR methodology
- scikit-learn ML capabilities

## License

[Add license information here]

## Support

For issues or questions:
- Review [ASOM_STRATEGY_PLAN.md](ASOM_STRATEGY_PLAN.md) for strategy details
- Check test suite for usage examples
- Consult code comments in strategies.py
