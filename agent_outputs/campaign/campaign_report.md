# Cross-Bundle Campaign Investigation Report

## Executive Summary

The campaign correlator analyzed **52 bundle(s)** and identified **10 campaign-level finding(s)**. The top finding was **Suspected Long-Running Malicious Infrastructure** with confidence **0.70**.

## Campaign Findings

### 1. Suspected Long-Running Malicious Infrastructure
- Severity: **MEDIUM**
- Confidence: **0.70**
- First Seen: N/A
- Last Seen: N/A
- Bundles: bundle_2025-11-18_nested_overlap, bundle_2025-12-03_nested_overlap, bundle_2025-12-04_nested_overlap, bundle_2025-12-05_nested_overlap, bundle_2025-12-06_nested_overlap, bundle_2025-12-07_nested_overlap, bundle_2025-12-08_nested_overlap, bundle_2025-12-09_nested_overlap, bundle_2025-12-10_nested_overlap, bundle_2025-12-11_nested_overlap, bundle_2025-12-12_nested_overlap, bundle_2025-12-13_nested_overlap, bundle_2025-12-14_nested_overlap, bundle_2025-12-15_nested_overlap, bundle_2025-12-16_nested_overlap, bundle_2025-12-17_nested_overlap, bundle_2025-12-18_nested_overlap, bundle_2025-12-19_nested_overlap, bundle_2025-12-20_nested_overlap, bundle_2025-12-21_nested_overlap, bundle_2025-12-24_nested_overlap, bundle_2025-12-31_nested_overlap, bundle_2026-01-02_nested_overlap, bundle_2026-01-03_nested_overlap, bundle_2026-01-04_nested_overlap, bundle_2026-01-05_nested_overlap, bundle_2026-01-06_nested_overlap, bundle_2026-01-08_nested_overlap, bundle_2026-01-10_nested_overlap, bundle_2026-01-11_nested_overlap, bundle_2026-01-14_nested_overlap, bundle_2026-01-15_nested_overlap, bundle_2026-01-16_nested_overlap, bundle_2026-01-18_nested_overlap, bundle_2026-01-19_nested_overlap, bundle_2026-01-21_nested_overlap, bundle_2026-01-23_nested_overlap, bundle_2026-01-24_nested_overlap, bundle_2026-01-25_nested_overlap, bundle_2026-01-26_nested_overlap, bundle_2026-01-27_nested_overlap, bundle_2026-01-28_nested_overlap, bundle_2026-01-29_nested_overlap
- Source Hosts: 103.180.111.173, 103.180.176.136, 136.144.42.225, 136.144.43.111, 138.199.59.143, 141.98.11.109, 141.98.11.114, 141.98.11.118, 141.98.11.127, 141.98.11.144, 141.98.11.170, 141.98.11.190, 141.98.11.49, 141.98.11.8, 141.98.11.81, 141.98.83.10, 141.98.83.70, 147.45.112.100, 147.45.112.108, 147.45.112.181, 147.45.112.182, 147.45.112.183, 147.45.112.185, 147.45.112.186, 147.45.112.188, 149.50.116.107, 150.242.202.185, 176.97.210.106, 178.20.129.235, 179.60.146.30, 179.60.146.31, 179.60.146.32, 179.60.146.33, 179.60.146.34, 179.60.146.35, 179.60.146.36, 179.60.146.37, 181.49.207.198, 185.147.124.201, 185.147.125.31, 185.16.39.19, 185.42.12.42, 193.111.248.57, 193.141.60.147, 193.3.19.42, 194.0.234.17, 194.0.234.31, 194.165.16.161, 194.165.16.162, 194.165.16.163, 194.165.16.164, 194.165.16.167, 194.165.16.18, 194.165.17.11, 209.15.109.92, 210.19.252.30, 45.130.145.6, 45.130.145.9, 45.135.232.124, 45.135.232.19, 45.135.232.20, 45.135.232.37, 45.141.84.95, 45.141.87.105, 45.141.87.151, 45.141.87.201, 45.141.87.46, 45.141.87.87, 45.227.254.151, 45.227.254.152, 45.227.254.154, 45.227.254.3, 45.92.177.109, 45.92.229.189, 57.129.133.249, 79.127.132.53, 80.64.30.118, 80.75.212.32, 80.75.212.45, 80.91.223.58, 85.237.194.86, 88.214.25.115, 88.214.25.121, 88.214.25.122, 88.214.25.123, 88.214.25.125, 91.199.163.12, 91.199.163.13, 91.224.92.23, 91.238.181.10, 91.238.181.39, 91.238.181.40, 91.238.181.6, 91.238.181.7, 91.238.181.8, 91.238.181.91, 91.238.181.92, 91.238.181.93, 91.238.181.94, 91.238.181.95, 91.238.181.96, 92.255.85.173, 92.255.85.174, 98.159.33.100, 98.159.33.18, 98.159.33.51
- Destination Hosts: 10.128.239.57
- MITRE ATT&CK: T1021.001, T1078, T1133
- Description: The entity `10.128.239.57` persisted across multiple bundles and hosts, suggesting campaign-level malicious activity rather than an isolated event.
- Recommendation: Perform retrospective scoping across all affected hosts, block associated infrastructure, and validate whether this activity represents sustained intrusion or command-and-control.
- Rationale:
  - Observed across 43 bundles
  - Persistence across many bundles
  - Observed from 106 source hosts
  - Mapped to MITRE ATT&CK techniques

### 2. Suspected Long-Running Malicious Infrastructure
- Severity: **MEDIUM**
- Confidence: **0.70**
- First Seen: N/A
- Last Seen: N/A
- Bundles: bundle_2025-11-18_nested_overlap, bundle_2025-12-03_nested_overlap, bundle_2025-12-04_nested_overlap, bundle_2025-12-05_nested_overlap, bundle_2025-12-07_nested_overlap, bundle_2025-12-08_nested_overlap, bundle_2025-12-09_nested_overlap, bundle_2025-12-11_nested_overlap, bundle_2025-12-12_nested_overlap, bundle_2025-12-14_nested_overlap, bundle_2025-12-15_nested_overlap, bundle_2025-12-16_nested_overlap, bundle_2025-12-17_nested_overlap, bundle_2025-12-18_nested_overlap, bundle_2025-12-19_nested_overlap, bundle_2025-12-20_nested_overlap, bundle_2025-12-21_nested_overlap, bundle_2026-01-02_nested_overlap, bundle_2026-01-04_nested_overlap, bundle_2026-01-05_nested_overlap, bundle_2026-01-06_nested_overlap, bundle_2026-01-08_nested_overlap, bundle_2026-01-10_nested_overlap, bundle_2026-01-11_nested_overlap, bundle_2026-01-14_nested_overlap, bundle_2026-01-16_nested_overlap, bundle_2026-01-18_nested_overlap, bundle_2026-01-19_nested_overlap, bundle_2026-01-21_nested_overlap, bundle_2026-01-23_nested_overlap, bundle_2026-01-24_nested_overlap, bundle_2026-01-25_nested_overlap, bundle_2026-01-26_nested_overlap, bundle_2026-01-27_nested_overlap, bundle_2026-01-28_nested_overlap, bundle_2026-01-29_nested_overlap
- Source Hosts: 10.128.239.57
- Destination Hosts: 103.180.111.173, 103.180.176.136, 136.144.42.225, 136.144.43.111, 138.199.59.143, 141.98.11.100, 141.98.11.109, 141.98.11.114, 141.98.11.127, 141.98.11.170, 141.98.11.49, 141.98.11.8, 141.98.11.81, 141.98.83.10, 141.98.83.70, 147.45.112.102, 147.45.112.108, 147.45.112.181, 147.45.112.185, 147.45.112.186, 147.45.112.188, 149.50.116.107, 150.242.202.185, 178.20.129.235, 179.60.146.31, 179.60.146.32, 179.60.146.33, 179.60.146.34, 179.60.146.35, 179.60.146.36, 179.60.146.37, 185.147.124.43, 185.147.125.31, 185.16.39.19, 185.42.12.42, 193.111.248.57, 193.3.19.42, 194.0.234.17, 194.0.234.31, 194.165.16.161, 194.165.16.167, 194.165.16.18, 194.165.16.26, 194.165.17.11, 195.211.190.189, 210.19.252.30, 210.89.44.129, 45.130.145.78, 45.135.232.124, 45.135.232.19, 45.135.232.20, 45.141.87.201, 45.141.87.46, 45.227.254.151, 45.227.254.152, 45.227.254.3, 45.92.229.189, 51.91.79.17, 79.127.132.53, 80.64.30.118, 80.75.212.32, 80.75.212.45, 85.237.194.86, 88.214.25.115, 88.214.25.121, 88.214.25.122, 88.214.25.123, 88.214.25.125, 91.199.163.12, 91.199.163.13, 91.238.181.10, 91.238.181.6, 91.238.181.7, 91.238.181.8, 91.238.181.91, 91.238.181.92, 91.238.181.93, 91.238.181.94, 91.238.181.95, 91.238.181.96, 92.255.85.173, 98.159.33.100, 98.159.33.51
- MITRE ATT&CK: T1041, T1048, T1071, T1105, T1567, T1573
- Description: The entity `10.128.239.57` persisted across multiple bundles and hosts, suggesting campaign-level malicious activity rather than an isolated event.
- Recommendation: Perform retrospective scoping across all affected hosts, block associated infrastructure, and validate whether this activity represents sustained intrusion or command-and-control.
- Rationale:
  - Observed across 36 bundles
  - Persistence across many bundles
  - Corroborated by 4 different indicators
  - Mapped to MITRE ATT&CK techniques

### 3. Suspected Long-Running Malicious Infrastructure
- Severity: **MEDIUM**
- Confidence: **0.70**
- First Seen: N/A
- Last Seen: N/A
- Bundles: bundle_2025-11-18_nested_overlap, bundle_2025-12-07_nested_overlap, bundle_2026-01-10_nested_overlap, bundle_2026-01-14_nested_overlap, bundle_2026-01-26_nested_overlap
- Source Hosts: 10.128.239.57
- Destination Hosts: 88.214.25.115
- MITRE ATT&CK: T1041, T1048, T1071, T1567, T1573
- Description: The entity `88.214.25.115` persisted across multiple bundles and hosts, suggesting campaign-level malicious activity rather than an isolated event.
- Recommendation: Perform retrospective scoping across all affected hosts, block associated infrastructure, and validate whether this activity represents sustained intrusion or command-and-control.
- Rationale:
  - Observed across 5 bundles
  - Persistence across many bundles
  - Corroborated by 2 different indicators
  - Mapped to MITRE ATT&CK techniques

### 4. Suspected Long-Running Malicious Infrastructure
- Severity: **MEDIUM**
- Confidence: **0.70**
- First Seen: N/A
- Last Seen: N/A
- Bundles: bundle_2025-11-18_nested_overlap, bundle_2025-12-07_nested_overlap, bundle_2025-12-19_nested_overlap, bundle_2026-01-27_nested_overlap, bundle_2026-01-29_nested_overlap
- Source Hosts: 10.128.239.57
- Destination Hosts: 91.238.181.7
- MITRE ATT&CK: T1041, T1048, T1071, T1567, T1573
- Description: The entity `91.238.181.7` persisted across multiple bundles and hosts, suggesting campaign-level malicious activity rather than an isolated event.
- Recommendation: Perform retrospective scoping across all affected hosts, block associated infrastructure, and validate whether this activity represents sustained intrusion or command-and-control.
- Rationale:
  - Observed across 5 bundles
  - Persistence across many bundles
  - Corroborated by 2 different indicators
  - Mapped to MITRE ATT&CK techniques

### 5. Suspected Long-Running DNS-Based C2 Activity
- Severity: **MEDIUM**
- Confidence: **0.70**
- First Seen: N/A
- Last Seen: N/A
- Bundles: bundle_2025-11-23_nested_overlap, bundle_2025-12-07_nested_overlap, bundle_2025-12-19_nested_overlap, bundle_2026-01-04_nested_overlap, bundle_2026-01-10_nested_overlap, bundle_2026-01-26_nested_overlap, bundle_2026-01-27_nested_overlap
- Source Hosts: 10.128.239.21
- Destination Hosts: 13.107.222.240, 185.159.197.3, 199.19.56.1, 205.251.193.165, 50.148.81.154
- MITRE ATT&CK: T1041, T1048, T1071.004, T1567
- Description: The entity `10.128.239.21` appeared repeatedly across bundles and hosts with DNS-related anomalies, suggesting sustained malicious DNS communication or command-and-control.
- Recommendation: Perform retrospective scoping across all affected hosts, block associated infrastructure, and validate whether this activity represents sustained intrusion or command-and-control.
- Rationale:
  - Observed across 7 bundles
  - Persistence across many bundles
  - Corroborated by 2 different indicators
  - Mapped to MITRE ATT&CK techniques

### 6. Suspected Long-Running Malicious Infrastructure
- Severity: **MEDIUM**
- Confidence: **0.70**
- First Seen: N/A
- Last Seen: N/A
- Bundles: bundle_2025-12-07_nested_overlap, bundle_2026-01-02_nested_overlap, bundle_2026-01-08_nested_overlap, bundle_2026-01-23_nested_overlap, bundle_2026-01-27_nested_overlap
- Source Hosts: 10.128.239.57
- Destination Hosts: 179.60.146.33
- MITRE ATT&CK: T1041, T1048, T1071, T1567, T1573
- Description: The entity `179.60.146.33` persisted across multiple bundles and hosts, suggesting campaign-level malicious activity rather than an isolated event.
- Recommendation: Perform retrospective scoping across all affected hosts, block associated infrastructure, and validate whether this activity represents sustained intrusion or command-and-control.
- Rationale:
  - Observed across 5 bundles
  - Persistence across many bundles
  - Corroborated by 2 different indicators
  - Mapped to MITRE ATT&CK techniques

### 7. Suspected Long-Running Malicious Infrastructure
- Severity: **MEDIUM**
- Confidence: **0.70**
- First Seen: N/A
- Last Seen: N/A
- Bundles: bundle_2025-12-08_nested_overlap, bundle_2025-12-19_nested_overlap, bundle_2026-01-14_nested_overlap, bundle_2026-01-18_nested_overlap, bundle_2026-01-29_nested_overlap
- Source Hosts: 10.128.239.57
- Destination Hosts: 194.165.17.11
- MITRE ATT&CK: T1041, T1048, T1071, T1567, T1573
- Description: The entity `194.165.17.11` persisted across multiple bundles and hosts, suggesting campaign-level malicious activity rather than an isolated event.
- Recommendation: Perform retrospective scoping across all affected hosts, block associated infrastructure, and validate whether this activity represents sustained intrusion or command-and-control.
- Rationale:
  - Observed across 5 bundles
  - Persistence across many bundles
  - Corroborated by 2 different indicators
  - Mapped to MITRE ATT&CK techniques

### 8. Suspected Long-Running Malicious Infrastructure
- Severity: **MEDIUM**
- Confidence: **0.70**
- First Seen: N/A
- Last Seen: N/A
- Bundles: bundle_2025-12-09_nested_overlap, bundle_2025-12-17_nested_overlap, bundle_2026-01-16_nested_overlap, bundle_2026-01-27_nested_overlap, bundle_2026-01-28_nested_overlap
- Source Hosts: 10.128.239.57
- Destination Hosts: 179.60.146.36
- MITRE ATT&CK: T1041, T1048, T1071, T1567, T1573
- Description: The entity `179.60.146.36` persisted across multiple bundles and hosts, suggesting campaign-level malicious activity rather than an isolated event.
- Recommendation: Perform retrospective scoping across all affected hosts, block associated infrastructure, and validate whether this activity represents sustained intrusion or command-and-control.
- Rationale:
  - Observed across 5 bundles
  - Persistence across many bundles
  - Corroborated by 2 different indicators
  - Mapped to MITRE ATT&CK techniques

### 9. Suspected Long-Running Malicious Infrastructure
- Severity: **MEDIUM**
- Confidence: **0.70**
- First Seen: N/A
- Last Seen: N/A
- Bundles: bundle_2025-12-11_nested_overlap, bundle_2026-01-04_nested_overlap, bundle_2026-01-05_nested_overlap, bundle_2026-01-06_nested_overlap
- Source Hosts: 10.128.239.57
- Destination Hosts: 45.227.254.3
- MITRE ATT&CK: T1041, T1048, T1071, T1567, T1573
- Description: The entity `45.227.254.3` persisted across multiple bundles and hosts, suggesting campaign-level malicious activity rather than an isolated event.
- Recommendation: Perform retrospective scoping across all affected hosts, block associated infrastructure, and validate whether this activity represents sustained intrusion or command-and-control.
- Rationale:
  - Observed across 4 bundles
  - Persistence across many bundles
  - Corroborated by 2 different indicators
  - Mapped to MITRE ATT&CK techniques

### 10. Suspected Long-Running Malicious Infrastructure
- Severity: **MEDIUM**
- Confidence: **0.70**
- First Seen: N/A
- Last Seen: N/A
- Bundles: bundle_2025-12-12_nested_overlap, bundle_2025-12-17_nested_overlap, bundle_2025-12-18_nested_overlap, bundle_2026-01-08_nested_overlap
- Source Hosts: 10.128.239.57
- Destination Hosts: 91.238.181.8
- MITRE ATT&CK: T1041, T1048, T1071, T1567, T1573
- Description: The entity `91.238.181.8` persisted across multiple bundles and hosts, suggesting campaign-level malicious activity rather than an isolated event.
- Recommendation: Perform retrospective scoping across all affected hosts, block associated infrastructure, and validate whether this activity represents sustained intrusion or command-and-control.
- Rationale:
  - Observed across 4 bundles
  - Persistence across many bundles
  - Corroborated by 2 different indicators
  - Mapped to MITRE ATT&CK techniques
