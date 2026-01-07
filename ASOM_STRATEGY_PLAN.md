# ASOM-Aligned Strategy Implementation Plan

## Overview

This document outlines the comprehensive plan for refactoring the 221B threat hunting platform to align with the **Analytic Scheme of Maneuver (ASOM)**. The ASOM provides a structured approach to answering Commander's Critical Information Requirements (CCIRs) through progressively sophisticated detection actions.

## ASOM Structure

- **23 CCIRs** covering MITRE ATT&CK tactics from Initial Access to Command & Control
- **144 Total Actions** across three sophistication levels:
  - **Level 1**: Rule-based detection (watchlists, correlation rules, pattern matching)
  - **Level 2**: Statistical baseline detection (anomaly scoring using historical baselines)
  - **Level 3**: Machine learning detection (supervised/unsupervised ML models)

## Architecture Changes

### Multi-Table Correlation Support
- Strategies will support correlation across multiple data sources (Zeek, Sysmon, Windows Events, etc.)
- New base class methods for joining data from multiple tables
- Efficient correlation using pandas merge/join operations

### Multiprocessing Enhancement
- Continue leveraging multiprocessing for performance
- Process-level parallelization for data-heavy operations
- Thread pools for I/O-bound correlation tasks

### ML Integration
- Implement Level 3 actions using scikit-learn (Isolation Forest, Random Forest, etc.)
- Support for both supervised and unsupervised learning
- Plain English explanations for ML decisions

## Strategy Implementation Plan

### Phase 1: Initial Access (TA0001) - 5 Strategies

#### Strategy 1: CompromisedCredentialsStrategy
**CCIR**: Has an adversary gained initial access using compromised credentials?

**Actions to Implement**:
- **Level 1**: Detect successful remote logins preceded by 20+ failed attempts from same IP
- **Level 2**: Statistical baseline of user login behavior (hours, geolocation, session volume)
- **Level 3**: Isolation Forest/One-Class SVM on session features (duration, bytes, processes)

**Data Sources**:
- Windows Event ID 4624, 4625
- Zeek conn.log
- Sysmon Event ID 1, 3

**Key Detection Logic**:
- Correlate failed auth attempts with successful logins
- Detect impossible travel scenarios
- Analyze post-login reconnaissance activity

#### Strategy 2: ThirdPartyAccessStrategy
**CCIR**: Is an adversary exploiting a trusted third-party relationship for initial access?

**Actions to Implement**:
- **Level 1**: Check third-party account logins against IP whitelist and threat intel
- **Level 2**: Baseline third-party account behavior patterns
- **Level 3**: ML model to detect anomalous third-party account activity

**Data Sources**:
- Windows Event ID 4624
- Zeek conn.log
- Active Directory group membership data

#### Strategy 3: RemovableMediaStrategy
**CCIR**: Is an adversary attempting to gain initial access via removable media?

**Actions to Implement**:
- **Level 1**: USB mount followed by process execution within 2 minutes
- **Level 2**: Statistical analysis of USB device usage patterns
- **Level 3**: Graph-based analysis of USB device spread across hosts

**Data Sources**:
- Windows Event ID 2003 (USB Mount)
- Sysmon Event ID 1 (Process Creation)
- Sysmon Event ID 11 (File Creation)

#### Strategy 4: ExternalRemoteServicesStrategy
**CCIR**: Has an adversary gained initial access by exploiting external remote services?

**Actions to Implement**:
- **Level 1**: Remote logins from external IPs with threat intel correlation
- **Level 2**: Baseline normal remote access patterns per service
- **Level 3**: ML anomaly detection on remote access behavior

**Data Sources**:
- Windows Event ID 4624, 4625
- Zeek conn.log, rdp.log, ssh.log
- Sysmon Event ID 1, 3

#### Strategy 5: PublicAppExploitStrategy
**CCIR**: Has an adversary successfully exploited a public-facing application to gain initial access?

**Actions to Implement**:
- **Level 1**: RCE patterns in HTTP logs followed by shell process execution
- **Level 2**: Statistical baseline of URI length, entropy, and process relationships
- **Level 3**: Random Forest/Gradient Boosting classifier for exploit detection

**Data Sources**:
- Zeek http.log
- Sysmon Event ID 1
- IIS/Apache/Nginx access logs

### Phase 2: Execution (TA0002) - 7 Strategies

#### Strategy 6: ScheduledTaskExecutionStrategy
**CCIR**: Is an adversary using scheduled tasks for remote code execution?

**Actions to Implement**:
- **Level 1**: Detect scheduled tasks with suspicious trigger types or commands
- **Level 2**: Baseline normal scheduled task creation patterns
- **Level 3**: ML classification of malicious task characteristics

**Data Sources**:
- Windows Event ID 4698, 4702
- Sysmon Event ID 1

#### Strategy 7: PowerShellExecutionStrategy
**CCIR**: Is the adversary executing malicious code using PowerShell?

**Actions to Implement**:
- **Level 1**: PowerShell commands with Base64 encoding, download cradles, obfuscation
- **Level 2**: Statistical baseline of PowerShell command line entropy and length
- **Level 3**: LSTM character-level model for malicious PowerShell detection

**Data Sources**:
- Windows Event ID 4103, 4104
- Sysmon Event ID 1
- Windows Event ID 4688

#### Strategy 8: WindowsCmdShellStrategy
**CCIR**: Is an adversary executing commands using the Windows Command Shell?

**Actions to Implement**:
- **Level 1**: cmd.exe with suspicious commands (whoami, net, ipconfig, etc.)
- **Level 2**: Baseline cmd.exe usage patterns per user
- **Level 3**: ML anomaly detection on command line patterns

**Data Sources**:
- Windows Event ID 4688
- Sysmon Event ID 1

#### Strategy 9: UnixShellStrategy
**CCIR**: Is the adversary executing malicious commands or scripts via a Unix shell?

**Actions to Implement**:
- **Level 1**: Shell commands with curl/wget downloads or suspicious utilities
- **Level 2**: Baseline shell command patterns per user
- **Level 3**: ML clustering of command line behaviors

**Data Sources**:
- auditd EXECVE logs
- Sysmon for Linux Event ID 1
- osquery process_events

#### Strategy 10: NetworkDeviceCommandsStrategy
**CCIR**: Is an adversary executing commands on our network devices?

**Actions to Implement**:
- **Level 1**: Configuration changes during off-hours or from unusual IPs
- **Level 2**: Baseline administrative command patterns
- **Level 3**: ML anomaly detection on device command sequences

**Data Sources**:
- TACACS+ command accounting logs
- Network device syslog
- NCM logs

#### Strategy 11: CloudAPIAbuseStrategy
**CCIR**: Is an adversary executing malicious commands by abusing cloud APIs?

**Actions to Implement**:
- **Level 1**: Unusual API calls (instance creation, IAM changes, data access)
- **Level 2**: Baseline cloud API usage patterns per identity
- **Level 3**: ML anomaly detection on cloud API sequences

**Data Sources**:
- AWS CloudTrail logs
- Azure Activity Logs
- Google Cloud Audit Logs

#### Strategy 12: ContainerExecutionStrategy
**CCIR**: Is an adversary executing commands within our containerized environments?

**Actions to Implement**:
- **Level 1**: Shell process execution from docker/kubectl parent
- **Level 2**: Baseline container command patterns
- **Level 3**: ML classification of malicious container activity

**Data Sources**:
- Docker daemon logs
- Kubernetes API audit logs
- Sysmon Event ID 1

### Phase 3: Persistence (TA0003) - 4 Strategies

#### Strategy 13: ScheduledTaskPersistenceStrategy
**CCIR**: Has an adversary established persistence via a scheduled task?

**Actions to Implement**:
- **Level 1**: Tasks with LogonTrigger/BootTrigger pointing to non-standard locations
- **Level 2**: Baseline task creation patterns and anomaly scoring
- **Level 3**: ML classification of persistent task characteristics

**Data Sources**:
- Windows Event ID 4698, 4702

#### Strategy 14: DormantAccountStrategy
**CCIR**: Is an adversary maintaining persistence using a legitimate but dormant or misused account?

**Actions to Implement**:
- **Level 1**: Service accounts with interactive logins
- **Level 2**: Statistical analysis of dormant account usage patterns
- **Level 3**: ML anomaly detection on account reactivation

**Data Sources**:
- Windows Event ID 4624
- Active Directory account data

#### Strategy 15: ExternalRemotePersistenceStrategy
**CCIR**: Is an adversary using external remote services to maintain persistent access?

**Actions to Implement**:
- **Level 1**: Long-duration remote sessions without logoff events
- **Level 2**: Baseline remote session duration patterns
- **Level 3**: ML anomaly detection on session characteristics

**Data Sources**:
- Windows Event ID 4624, 4647, 4634
- Zeek conn.log

#### Strategy 16: WebShellPersistenceStrategy
**CCIR**: Has an adversary established persistent access by deploying a web shell?

**Actions to Implement**:
- **Level 1**: Script file creation by web server process + YARA scanning
- **Level 2**: Baseline web directory file creation patterns
- **Level 3**: ML classification of web shell file characteristics

**Data Sources**:
- Sysmon Event ID 11
- Zeek files.log
- IIS/Apache/Nginx access logs

### Phase 4: Privilege Escalation (TA0004) - 2 Strategies

#### Strategy 17: ScheduledTaskPrivEscStrategy
**CCIR**: Is an adversary abusing scheduled tasks to escalate privileges?

**Actions to Implement**:
- **Level 1**: Non-privileged user creates task with privileged principal
- **Level 2**: Baseline privilege escalation patterns
- **Level 3**: ML anomaly detection on privilege transitions

**Data Sources**:
- Windows Event ID 4698, 4702
- Active Directory group membership

#### Strategy 18: CompromisedAccountEscalationStrategy
**CCIR**: Is an adversary escalating privileges using a compromised account?

**Actions to Implement**:
- **Level 1**: Privileged group modifications by non-admin accounts
- **Level 2**: Statistical baseline of admin group modification patterns
- **Level 3**: Isolation Forest on privilege escalation events

**Data Sources**:
- Windows Event ID 4728, 4732, 4756
- Active Directory data

### Phase 5: Defense Evasion (TA0005) - 1 Strategy

#### Strategy 19: ValidAccountMasqueradeStrategy
**CCIR**: Is an adversary using a valid account to bypass security controls or masquerade as a legitimate user?

**Actions to Implement**:
- **Level 1**: Suspicious command line patterns (whoami, net, disable AV)
- **Level 2**: TF-IDF analysis of command line baselines per user
- **Level 3**: LDA topic modeling to cluster command line behaviors

**Data Sources**:
- Windows Event ID 4688
- Sysmon Event ID 1

### Phase 6: Lateral Movement (TA0008) - 1 Strategy

#### Strategy 20: RemovableMediaLateralStrategy
**CCIR**: Is an adversary attempting to move laterally using removable media?

**Actions to Implement**:
- **Level 1**: Autorun.inf or malicious LNK files on removable drives
- **Level 2**: Baseline file write patterns on removable media per user
- **Level 3**: Graph analysis of file propagation across hosts

**Data Sources**:
- Sysmon Event ID 11
- USB device events

### Phase 7: Command & Control (TA0011) - 3 Strategies

#### Strategy 21: HTTPC2Strategy
**CCIR**: Is an adversary using web protocols (HTTP/HTTPS) for command and control communications?

**Actions to Implement**:
- **Level 1**: Threat intel correlation on HTTP destinations and User-Agents
- **Level 2**: Statistical baseline of HTTP byte ratios and beaconing patterns
- **Level 3**: Time-series decomposition + LSTM for C2 traffic detection

**Data Sources**:
- Zeek http.log, conn.log, dns.log

#### Strategy 22: DNSC2Strategy
**CCIR**: Is an adversary using the Domain Name System (DNS) protocol for command and control communications?

**Actions to Implement**:
- **Level 1**: Suspicious processes making DNS queries + threat intel correlation
- **Level 2**: Baseline DNS query patterns per process with risk scoring
- **Level 3**: Random Forest classifier on DNS query features

**Data Sources**:
- Zeek dns.log
- Sysmon Event ID 22
- Windows Event ID 22

#### Strategy 23: NonAppLayerC2Strategy
**CCIR**: Is an adversary using a non-application layer protocol for command and control?

**Actions to Implement**:
- **Level 1**: UDP/ICMP traffic to known C2 IPs from threat intel
- **Level 2**: Statistical baseline of UDP/ICMP traffic patterns
- **Level 3**: DBSCAN clustering on UDP flows + ARIMA time-series for ICMP

**Data Sources**:
- Zeek conn.log
- Zeek icmp.log
- Windows Event ID 5156

## Implementation Order

We will implement strategies **one at a time** in the following order:

1. **CompromisedCredentialsStrategy** (CCIR 1) - Most critical, high detection value
2. **PublicAppExploitStrategy** (CCIR 5) - Common attack vector
3. **PowerShellExecutionStrategy** (CCIR 7) - Widely used for execution
4. **WebShellPersistenceStrategy** (CCIR 16) - Critical persistence mechanism
5. **CompromisedAccountEscalationStrategy** (CCIR 18) - Privilege escalation detection
6. **HTTPC2Strategy** (CCIR 21) - Most common C2 channel
7. **DNSC2Strategy** (CCIR 22) - Covert C2 channel
8. Continue with remaining strategies in CCIR order...

## Testing Strategy

For each implemented strategy:
1. Create unit tests for all three sophistication levels
2. Test with synthetic data representing normal and malicious patterns
3. Validate multiprocessing performance
4. Ensure ML models trigger and provide explanations
5. Test correlation across multiple data sources

## Success Criteria

- All 23 CCIRs have corresponding strategies
- Each strategy implements applicable sophistication levels (1-3)
- Multiprocessing maintained for performance
- ML integration with plain English explanations
- Comprehensive test coverage
- Security validation with CodeQL
- Documentation updated to reflect ASOM alignment

## Next Steps

1. Create base infrastructure for multi-table correlation
2. Implement Strategy 1: CompromisedCredentialsStrategy with all 3 levels
3. Test thoroughly and iterate
4. Proceed to Strategy 2
5. Repeat until all 23 strategies are complete
