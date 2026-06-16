# Incident Investigation Report: Azure Honeypot Monitoring with Sentinel

## 1. Executive Summary

This report documents the analysis of attack traffic captured by an internet-facing
Windows Server honeypot deployed on Microsoft Azure. Over the monitoring period, the
honeypot recorded a high volume of brute-force authentication attempts, of which a
subset resulted in successful logons. This report details the attack timeline,
indicators of compromise, MITRE ATT&CK mapping, and recommended remediation.

| Field | Value |
|---|---|
| Report date | 16/06/2026 |
| Monitoring period | 12/06/2026 – 14/06/2026 |
| Asset under investigation | HP-Admin |
| Severity | Low: high attack volume, zero confirmed external compromise |
| Analyst | Sushil Dhungana |

## 2. Scope and Environment

- **Asset**: Windows Server VM hosted on Azure, internet-facing
- **Exposure**: All ports open via Network Security Group
- **Log source**: Windows Security Event Log, collected via Azure Monitor Agent
- **SIEM**: Microsoft Sentinel (Log Analytics workspace)
- **Purpose**: Controlled research environment for observing real-world attack
  behavior; no production data or third-party assets involved

## 3. Attack Overview

### 3.1 Volume and Origin

| Metric | Value |
|---|---|
| Total failed login attempts (EventID 4625) | 123,103 |
| Unique source IP addresses | 265 |
| Countries observed | 46 |
| Top attacking location | Perth (Australia) |
| Top attacking IP address | 194.180.48.162 |
| Total attempts from top IP | 37,413 |

### 3.2 Timeline

| Metric | Value |
|---|---|
| First recorded attack attempt | 12/06/2026, 20:52:08.249 |
| Last recorded attack attempt | 14/06/2026, 21:57:19.948 |
| Peak attack hour | 13/06/2026, 22:00:00.000 |
| Peak attack count | 6,292 |
| Attack pattern | Continuous baseline scanning with two bursty surges |

## 4. Successful Authentication Event Findings

EventID 4624 was used to identify successful logons. Each successful logon was
cross-referenced against its source IP, logon type, and timestamp to determine
whether it originated from an external attacker or from legitimate activity.

**Finding: No successful logons originated from an external attacker IP.** All
4624 events that were not filtered out as `SYSTEM` or `ANONYMOUS LOGON` were
attributed to one of the following:

| Source | Description |
|---|---|
| Analyst's own administrative access | Logons from the analyst's known IP address(es) used for VM management and monitoring |
| Automatic Windows service/system logons | LogonType 5 (service) and other system-initiated authentication not tied to external actors |

| Field | Value |
|---|---|
| Total raw successful logons (4624) | 307 |
| Successful logons attributable to analyst | 16 |
| Successful logons attributable to Windows system processes | 291 |
| Successful logons attributable to external attackers | 0 |

### 4.1 Logon Type Reference

| Logon Type | Meaning | Relevance here |
|---|---|---|
| 0 | System (used internally by Windows, not a real user logon) | Not user-originated; irrelevant for attack analysis |
| 2 | Interactive (local console logon) | Likely admin/analyst or local activity; not external |
| 3 | Network (e.g. SMB, file shares, remote access over network) | Reviewed: no evidence of external successful logons |
| 5 | Service logon (Windows services starting under service accounts) | Routine system activity; not attack-related |
| 7 | Unlock (workstation unlock after logon session) | Local session activity; indicates active internal user session |

## 5. Process Execution Review

Process creation events (EventID 4688) occurring around successful logon sessions
were reviewed to confirm there was no unauthorized post-access activity.

No evidence of unauthorized command execution, persistence mechanisms, lateral
movement, or data exfiltration was found.

## 6. MITRE ATT&CK Mapping

Because no external compromise was confirmed, mapping is limited to the
**attempted** tactic observed at the network/credential layer rather than a full
attack chain.

| Tactic | Technique ID | Technique Name | Evidence | Outcome |
|---|---|---|---|---|
| Credential Access | T1110 | Brute Force | High volume of EventID 4625 from external source IPs | Attempted only (no successful breach) |
| Initial Access | T1078 | Valid Accounts | N/A | Not achieved by any external actor |
| Reconnaissance | T1595 | Active Scanning | Sustained probing of exposed RDP/SMB ports across the monitoring period | Confirmed |

## 7. Indicators of Compromise (IOCs)

Since no compromise occurred, these IOCs reflect observed **attack attempts**, not
confirmed breach artifacts.

| Type | Value |
|---|---|
| Top source IPs | 194.180.48.162, 80.94.95.83, 
49.0.33.162 |
| Targeted account name(s) | Administrator, Admin, User |
| Targeted hostname | HP-Admin |
| Malicious processes identified | None |

## 8. Detection Coverage

A scheduled analytics rule was created in Microsoft Sentinel to automatically
detect brute-force activity:

- **Rule name**: Brute Force Detection
- **Logic**: Flags source IPs with 5+ failed logon attempts (EventID 4625) within a
  24-hour window
- **MITRE tactic mapped in rule**: Credential Access (T1110)
- **Alert/incident generated**: None

## 9. Root Cause / Risk Assessment

The honeypot was deliberately configured with open ports (including RDP and SMB) to attract
external scanning and brute-force traffic, which it did at high volume. Despite
this, the account credentials in place (enforced by Azure's password complexity
policy, i.e. minimum 12 characters, no simple usernames) were not compromised during
the monitoring period. This indicates that **strong credential policy and the
absence of account lockout exploitation were sufficient to prevent brute-force
success** even under sustained, high-volume attack traffic.

## 10. Recommendations

Even though no compromise occurred, the following controls would further reduce
risk in a comparable production deployment:

1. **Restrict RDP/SMB exposure** by using a VPN, Azure Bastion, or just-in-time (JIT)
   VM access instead of direct internet exposure, to reduce the attack surface
   rather than relying solely on credential strength.
2. **Enforce account lockout policy** after a small number of failed attempts to
   slow down brute-force tooling.
3. **Enable Multi-Factor Authentication (MFA)** for all remote access as a
   defense-in-depth measure.
4. **Deploy automated IP blocking** for source IPs exceeding a failed-attempt
   threshold (e.g. via Sentinel playbooks/Logic Apps).
5. **Continue monitoring** EventID 4625/4624 patterns to detect any future shift
   from attempted to successful access.
6. **Maintain clear separation** between analyst administrative access and
   monitored attack traffic (e.g. by excluding known-good IPs from detection
   queries) to reduce investigation noise in future analyses.

## 11. Conclusion

This investigation captured a sustained, high-volume brute-force campaign against
an internet-facing honeypot, with peaks exceeding 6,000 failed attempts per hour.
Despite this volume, **no external actor successfully authenticated to the system**
as all successful logons and process executions were verified as belonging to the
analyst's own access or routine Windows system behavior. This is a strong outcome
that demonstrates the effectiveness of Azure's enforced password complexity policy
against brute-force attacks, while also validating the detection and investigation
workflow built for this project: collecting logs, building detection rules,
correlating identity and process data, and verifying findings before drawing
conclusions as required in real-world SOC incident response.

---

*This investigation was conducted in a controlled, isolated lab environment for
educational purposes. No production systems or third-party assets were affected.*
