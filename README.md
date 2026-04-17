# SC4063 – Agentic AI Network Forensics

**Module**: SC4063 Network Security  
**Presentation**: [Presentation.pdf](Presentation.pdf)     
**Demo Video**: https://www.youtube.com/watch?v=ZIO8DkfuFMo

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Key Capabilities](#2-key-capabilities)
3. [System Architecture](#3-system-architecture)
4. [Component Breakdown](#4-component-breakdown)
5. [Detection Logic](#5-detection-logic)
6. [Agentic Investigation Mode](#6-agentic-investigation-mode)
7. [Confidence Scoring & Uncertainty Quantification](#7-confidence-scoring--uncertainty-quantification)
8. [MITRE ATT&CK Mapping](#8-mitre-attck-mapping)
9. [Installation & Requirements](#9-installation--requirements)
10. [How to Run](#10-how-to-run)
11. [Output Structure](#11-output-structure)
12. [Configuration](#12-configuration)
13. [Data Models](#13-data-models)

---

## 1. Project Overview

This project implements an **agentic AI-driven network forensics pipeline** that analyses PCAP (packet capture) files to detect malicious network behaviour. Rather than running a fixed sequence of tools, the system uses a reasoning loop where an AI agent autonomously decides which analysis tools to invoke based on what it has already found — modelling a real analyst's iterative investigation process.

The pipeline transforms raw PCAP files into structured threat findings through 11 distinct processing phases, from initial file discovery through to a synthesised master forensics report. The system can detect a wide range of threat categories including command-and-control beaconing, DNS tunnelling, data exfiltration, lateral movement, and suspicious external access.

The core design philosophy is a **data refinery model**: PCAP data is preprocessed into normalised, structured evidence before AI-driven analysis begins. This separates concerns, enables incremental processing, and ensures that every finding is traceable back to its source packets.

---

## 2. Key Capabilities

| Capability | Description |
|---|---|
| Multi-vector threat detection | Beaconing, DNS tunnelling, lateral movement, data exfiltration, external access, TLS anomalies |
| Agentic investigation | LLM (Ollama) autonomously selects and sequences analysis tools across multiple reasoning rounds |
| Rule-based fallback | Fully functional deterministic analysis mode when LLM is unavailable |
| MITRE ATT&CK alignment | Automatic mapping of findings to ATT&CK techniques |
| Confidence scoring | Evidence-based probabilistic scoring with corroboration and diversity bonuses |
| Uncertainty quantification | Explicit false positive risks, missed detection risks, and analytical limitations per finding |
| Campaign correlation | Cross-bundle entity tracking to identify coordinated multi-stage attacks |
| Forensic provenance | Every finding traces back to source PCAP and raw network events |
| Web dashboard | Flask-based UI for upload, pipeline execution, and result browsing |
| Incremental processing | Idempotent phases that can be rerun; parallelisable extraction |

---

## 3. System Architecture

The pipeline is structured as an **11-phase data refinery**:

```
Phase 1:  File Ingestion        → Discover PCAPs, compute SHA256 hashes
Phase 2:  Metadata Enrichment   → Extract duration, packet count, timestamps (capinfos)
Phase 3:  Processing Plan       → Detect overlaps, duplicates, nesting relationships
Phase 4:  Extraction Plan       → Plan tshark extraction tasks per time chunk
Phase 5:  Evidence Extraction   → Execute tshark extraction; produce normalised events
Phase 6:  Bundle Construction   → Group events into logical investigation cases
Phase 7:  Summary Construction  → Generate LLM-readable summaries and retrieval documents
Phase 8:  Interface Validation  → Validate agent interface against extracted data
Phase 9:  Agentic Investigation → LLM-driven or rule-based forensic analysis
Phase 10: Campaign Analysis     → Cross-bundle correlation and campaign-level insights
Phase 11: Master Synthesis      → Aggregate all findings into a unified master report
```

All pipeline state is persisted in a central **SQLite evidence registry** (`evidence_registry.db`), enabling phases to be resumed, replayed, or run selectively.

**High-Level Data Flow:**

```
Raw PCAP Files
      │
      ▼
[Ingestion Phases 1–7]
      │  evidence_registry.db
      │  ai_handoff_bundles/
      │  preai_summaries/
      ▼
[Agent Interface Layer]
      │  Structured events, summaries, retrieval docs
      ▼
[Investigation Phases 9–11]
      │  LLM reasoning loop <——> Analyzer tools
      ▼
[agent_outputs/]
   report.json / report.md  (per bundle)
   campaign_report.md
   master_report.md
```

---

## 4. Component Breakdown

### `agent/` — Core Investigation Logic

The intelligence layer of the system. Contains all detection analyzers, the agentic reasoning loop, hypothesis management, and reporting.

| File | Purpose |
|---|---|
| `agentic_service.py` | LLM-driven investigation loop — Ollama model autonomously selects tools across up to 8 reasoning rounds |
| `service.py` | Rule-based deterministic fallback — runs all analyzers sequentially |
| `dns.py` | DNS anomaly detection: entropy scoring, DGA patterns, subdomain variation, tunnelling indicators |
| `http.py` | HTTP anomaly detection: suspicious user agents, unusual methods, long URIs, deep subdomains |
| `tls.py` | TLS anomaly detection: missing SNI, known-bad JA3 fingerprints, TLS on non-standard ports |
| `beaconing.py` | C2 beaconing detection: periodicity analysis of repeated connections by (src, dst, port) tuple |
| `intel.py` | IP reputation: cross-references destinations against known-bad IP list with configurable risk scores |
| `smb.py` | Lateral movement detection: SMB scanning (port 445) and EPM enumeration (port 135) |
| `external_access.py` | External access detection: flags inbound connections to sensitive ports (RDP 3389, SSH 22, etc.) |
| `volumetric.py` | Exfiltration detection: high session counts and large byte transfers to external destinations |
| `correlation.py` | Cross-signal correlation: identifies hosts exhibiting multiple independent threat indicators |
| `hypothesis_engine.py` | Generates, scores, and manages hypotheses; applies confidence bonuses and guardrails |
| `reporter.py` | Materialises hypotheses into structured findings with recommendations |
| `llm.py` | Ollama API integration: multi-turn tool-calling conversation management |
| `tools.py` | Tool definitions and executor for LLM-driven dynamic analysis |
| `campaign.py` | Aggregates bundle findings into campaign-level patterns and timelines |
| `campaign_reporter.py` | Generates campaign reports with entity correlation and MITRE mapping |
| `mitre.py` | Maps hypothesis types to MITRE ATT&CK technique IDs |
| `models.py` | Core data classes: `Evidence`, `Hypothesis`, `Finding`, `InvestigationResult` |
| `config.py` | All configurable thresholds, allowlists, internal IP ranges, known-bad IPs |
| `utils.py` | Utility functions: Shannon entropy calculation, severity ranking |

### `injestion/` — Data Pipeline (Preprocessing)

Handles all pre-AI processing: transforming raw PCAPs into structured, normalised events ready for analysis.

| File | Phase | Purpose |
|---|---|---|
| `discover_pcaps.py` | 1 | Recursively scans input directory; registers PCAPs with SHA256 hashes |
| `extract_metadata.py` | 2 | Invokes `capinfos` to extract packet count, duration, timestamps |
| `build_processing_plan.py` | 3 | Detects PCAP overlaps, duplicates, nesting; sets processing priority |
| `build_extraction_plan.py` | 4 | Creates extraction tasks (flow, DNS, HTTP, TLS, IOC, timeline) over time-chunked segments |
| `extraction_executor.py` | 5 | Runs `tshark` with field-based filters; normalises output to event schema |
| `build_ai_handoff.py` | 6 | Groups events into time-bucketed bundles for investigation |
| `build_preai_summaries.py` | 7 | Produces LLM-readable summaries and semantic retrieval documents |
| `registry.py` | — | SQLite schema and ORM-like interface for all pipeline state |

### `pipeline_runner.py` — Orchestration

Central orchestrator for all 11 phases. Supports configurable phase ranges, parallelised extraction workers, per-phase error handling, and JSON metrics output.

### `agent_interface.py` / `agent_interface_cli.py` — Query & Investigation API

Programmatic interface between preprocessed evidence and the investigation layer.

**Available methods:**
- `list_bundles()` — list all investigation cases
- `get_bundle_summary()` — high-level overview of a bundle
- `search_retrieval_docs()` — keyword search within bundle evidence
- `fetch_detailed_events()` — query events by type, IP, port, or keyword
- `get_pcaps()` — retrieve PCAP metadata for a bundle
- `investigate()` — run rule-based forensic analysis on a bundle
- `agentic_investigate()` — run LLM-driven agentic investigation
- `campaign_investigate()` — run campaign-level cross-bundle correlation

### `master_report_synthesizer.py` — Final Aggregation

Aggregates all per-bundle and campaign reports into a unified master investigation report. Optionally invokes the LLM for a final narrative synthesis across all findings.

### `web_app.py` — Web Dashboard (Flask)

Interactive browser interface for the pipeline.

**Features:**
- PCAP upload with drag-and-drop
- Live pipeline log streaming via Server-Sent Events (SSE)
- Pipeline configuration and execution controls
- Metrics dashboard (runtime per phase, finding counts, estimated cost)
- Results browser and markdown report viewer
- File management (upload, delete)

Access at: `http://localhost:5000`

---

## 5. Detection Logic

### DNS Anomaly Detection (`dns.py`)

Computes Shannon entropy scores for each queried domain. Suspicious indicators:

- **Entropy >= 3.8** — high-entropy domain label (DGA or tunnelling)
- **Long subdomain labels** — individual label length above threshold
- **Multi-host domain queries** — same domain queried by 5+ distinct internal hosts
- **Repetition** — same high-entropy domain queried repeatedly from one host

Combined score formula:
```
score = base_entropy_score + label_length_bonus + repetition_bonus + query_type_bonus
```
Capped at 1.0. Allowlisted CDN/cloud domains (Microsoft, Google, Akamai, Cloudflare, Fastly) are excluded to reduce false positives.

### HTTP Anomaly Detection (`http.py`)

Flags connections based on:

- **Suspicious user agents**: curl, wget, python-requests, powershell, nmap, masscan, scrapy, Go-http-client
- **Unusual HTTP methods**: PUT, DELETE, TRACE, CONNECT on non-proxy hosts
- **Long URIs**: path length > 120 characters (command passing)
- **Deep subdomains**: 4+ dot-separated labels in the hostname

### TLS Anomaly Detection (`tls.py`)

Identifies:

- **Known-bad JA3 fingerprints**: matches against a configurable set of malware-associated fingerprints
- **Missing SNI**: TLS handshakes without a Server Name Indication field, except on ports where TLS is expected without SNI (RDP 3389, LDAPS 636, LDAP 389, etc.)
- **Repeated missing-SNI**: 3+ connections from the same source without SNI (scored higher)
- **TLS on non-standard ports**: TLS observed on ports not in the standard set (443, 8443, 465, 993, 995)

### Beaconing Detection (`beaconing.py`)

Groups connections by the 4-tuple `(src_ip, dst_ip, dst_port, protocol)` and analyses timing intervals:

```
periodicity = 1.0 - (stddev(intervals) / mean(intervals))
```

Requirements: minimum 4 observed connections. Flagged if `periodicity > 0.75`. Higher periodicity indicates highly regular, automated communication consistent with C2 beacons.

### IP Reputation (`intel.py`)

Cross-references each destination IP against a configurable known-bad IP list. Each entry carries a risk score (0.0–1.0). Produces evidence for any matching destination.

### Lateral Movement Detection (`smb.py`)

Two patterns:

- **SMB scanning**: connections to port 445 across 5+ unique internal IP targets from one source — lateral movement score: `0.4 + (0.05 x target_count)`, capped at 0.95
- **EPM enumeration**: connections to port 135 (RPC endpoint mapper), used to enumerate services before lateral movement

### External Access Detection (`external_access.py`)

Flags inbound connections from external (non-RFC1918) IPs to sensitive internal ports:

| Port | Service | Score |
|---|---|---|
| 3389 | RDP | 0.85 |
| 22 | SSH | 0.75 |
| 5985/5986 | WinRM | 0.80 |
| 21 | FTP | 0.70 |
| 23 | Telnet | 0.80 |
| 445 | SMB | 0.90 |

### Volumetric / Exfiltration Detection (`volumetric.py`)

Flags outbound sessions to external IPs that exceed:
- **5+ sessions** to the same external destination
- **50 MB or more** total bytes transferred outbound

Higher scores are assigned when exfiltration occurs over port 443 (HTTPS), which blends with normal encrypted traffic.

### Cross-Signal Correlation (`correlation.py`)

Identifies hosts that appear across multiple independent evidence signals. A host triggering DNS anomalies, beaconing, and external access simultaneously receives a composite high-confidence finding that no single analyzer could produce alone.

---

## 6. Agentic Investigation Mode

When Ollama is available, the system enters an agentic loop modelled after analyst reasoning:

```
[Read Bundle Summary]
        |
        v
[LLM decides: which tool to run next?]
        |
        v
[Tool executes (analyzer / event query)]
        |
        v
[LLM reviews results, updates internal state]
        |
        v
[Repeat up to 8 rounds, or until LLM decides to finalise]
        |
        v
[LLM produces final narrative and structured findings]
```

**Available tools for the LLM:**

| Tool | Function |
|---|---|
| `run_dns_analysis` | Shannon entropy DNS scanning |
| `run_http_analysis` | HTTP anomaly detection |
| `run_tls_analysis` | TLS fingerprint and SNI analysis |
| `run_beaconing_analysis` | C2 periodicity detection |
| `run_ip_reputation` | Threat intelligence IP lookup |
| `run_smb_analysis` | Lateral movement detection |
| `run_external_access_analysis` | External access scanning |
| `run_volumetric_analysis` | Exfiltration detection |
| `query_events` | Fetch raw events filtered by type/IP/port |

The LLM system prompt aligns the investigation toward MITRE ATT&CK categories: Initial Access, Execution, Lateral Movement, Command & Control, Exfiltration, and Credential Access.

**Graceful fallback:** If Ollama is unavailable or the LLM fails to respond, the system transparently falls back to the deterministic rule-based mode, running all analyzers sequentially and applying the same hypothesis/confidence framework.

---

## 7. Confidence Scoring & Uncertainty Quantification

### Confidence Score Calculation

Each hypothesis is scored as follows:

```
base_score       = mean(evidence_scores)
corroboration    = min(0.20,  +0.05 x (evidence_count - 1))
diversity_bonus  = min(0.10,  +0.05 x (unique_analyzer_sources - 1))
severity_bonus   = +0.03 (LOW) | +0.05 (MEDIUM) | +0.08 (HIGH/CRITICAL)

final_confidence = min(1.0, base_score + corroboration + diversity_bonus + severity_bonus)
```

Only findings with `confidence >= 0.60` are included in the final report. A maximum of 10 findings are reported per bundle, sorted by confidence then severity.

### Uncertainty Quantification

Every finding explicitly documents:

- **False positive risks** — known benign explanations for the observed signals (e.g., CDN services causing high DNS entropy, legitimate admin tools with suspicious user agents)
- **Missed detection risks** — classes of threats the finding might fail to catch (e.g., slow-and-low beacons below the minimum observation threshold)
- **Analytical limitations** — scope boundaries of the analysis (e.g., metadata-only, no payload decryption, incomplete handshakes)

Findings with `confidence < 0.60` are flagged as requiring human review and not promoted to the final report.

---

## 8. MITRE ATT&CK Mapping

Each finding is automatically mapped to relevant ATT&CK techniques via `agent/mitre.py`:

| Detection Type | MITRE Technique |
|---|---|
| DNS Tunnelling | T1071.004 – Application Layer Protocol: DNS |
| DNS DGA / High-Entropy | T1584.004 – Compromise Infrastructure: Domains |
| HTTP C2 | T1071.001 – Application Layer Protocol: Web Protocols |
| TLS C2 | T1573.002 – Encrypted Channel: Asymmetric Cryptography |
| Beaconing | T1071 – Application Layer Protocol |
| Lateral Movement (SMB) | T1021.002 – Remote Services: SMB/Windows Admin Shares |
| External RDP / SSH | T1133 – External Remote Services |
| Data Exfiltration | T1048 – Exfiltration Over Alternative Protocol |
| IP Reputation Hit | T1071 – Application Layer Protocol |

Campaign reports additionally provide a consolidated MITRE ATT&CK matrix view across all bundles.

---

## 9. Installation & Requirements

### System Requirements

- Python 3.8
- `tshark` (Wireshark CLI) installed and in `$PATH`
- `capinfos` (bundled with Wireshark)
- Internet access recommended for IOC lookups
- [Ollama](https://ollama.com) — optional, required only for agentic mode

### Python Dependencies

Install all Python packages:

```bash
pip install -r requirements.txt
```

Key dependencies:

| Package | Purpose |
|---|---|
| `flask >= 3.0` | Web dashboard |
| `sqlite3` | Evidence registry (Python stdlib) |
| Standard library | `subprocess`, `json`, `hashlib`, `statistics`, `pathlib`, `datetime` |

### Ollama Setup (for Agentic Mode)

```bash
# Install Ollama from https://ollama.com
ollama pull llama3.1        # or any capable instruction-following model
ollama serve                # start the local LLM server
```

---

## 10. How to Run

### Option 1: Full Pipeline (Recommended)

```bash
python3 pipeline_runner.py --input-dir input_pcaps/
```

Runs all 11 phases in sequence. Outputs appear in `agent_outputs/`.

### Option 2: Full Pipeline with Agentic Mode

```bash
python3 pipeline_runner.py --input-dir input_pcaps/ --agentic --ollama-model llama3.1
```

### Option 3: Bash Script

```bash
bash run_pipeline.sh
```

### Option 4: Web Dashboard

```bash
python3 web_app.py
```

Open `http://localhost:5000`. Upload PCAP files, configure pipeline options, and execute from the UI. Results can be browsed directly in the dashboard.

### Option 5: CLI Investigation Only (on pre-processed data)

```bash
# List available bundles
python3 agent_interface_cli.py --db-path evidence_registry.db list-bundles

# Run rule-based investigation on all bundles
python3 agent_interface_cli.py investigate-all --outdir agent_outputs/

# Run agentic investigation (requires Ollama)
python3 agent_interface_cli.py agentic-investigate-all --ollama-model llama3.1 --outdir agent_outputs/
```

### Option 6: Selective Phase Execution

```bash
# Re-run only the investigation phase
python3 pipeline_runner.py --start-phase 9 --end-phase 11

# Re-run only extraction with parallelism
python3 pipeline_runner.py --start-phase 5 --end-phase 5 --workers 4
```

---

## 11. Output Structure

After a pipeline run completes, the following outputs are produced:

```
agent_outputs/
├── bundle_<timestamp>_<name>/
│   ├── report.json              <- Structured findings (machine-readable)
│   ├── report.md                <- Markdown forensics report (human-readable)
│   └── metrics.json             <- Per-bundle analysis timing and stats
├── campaign/
│   ├── campaign_report.json     <- Cross-bundle entity correlation
│   └── campaign_report.md       <- Campaign-level narrative report
└── master/
    ├── master_report.json       <- Unified aggregated findings
    └── master_report.md         <- Master forensics report

evidence_registry.db             <- SQLite: all pipeline state
pipeline_run_metrics.json        <- Per-phase timing, errors, estimated cost
pipeline_run_<timestamp>.txt     <- Full execution log

ai_handoff_bundles/              <- Structured JSON cases passed to the agent
preai_summaries/                 <- LLM-readable bundle summaries
preai_retrieval/                 <- Semantic retrieval document snippets
```

### Sample Finding (from report.json)

```json
{
  "title": "C2 Beaconing Activity Detected",
  "severity": "HIGH",
  "confidence": 0.87,
  "mitre_techniques": ["T1071"],
  "recommendation": "Isolate 192.168.1.105. Block destination at firewall. Conduct memory forensics.",
  "affected_entities": ["192.168.1.105 -> 203.0.113.50:443"],
  "false_positive_risks": ["Scheduled software update checks", "Telemetry services"],
  "missed_detection_risks": ["Sub-threshold beacons (< 4 observations)", "Jitter-randomised intervals"],
  "limitations": ["Network metadata only — payload not inspected"]
}
```

---

## 12. Configuration

All detection thresholds, allowlists, and network parameters are centralised in `agent/config.py`:

```python
# Reporting threshold
min_confidence_to_report = 0.60       # Minimum confidence to include a finding

# DNS analysis
entropy_threshold = 3.8               # Shannon entropy threshold for domain labels
dns_min_hosts_for_multihost = 5       # Unique hosts querying the same domain

# Beaconing
beacon_min_repeats = 4                # Minimum connections to assess periodicity
beacon_periodicity_threshold = 0.75   # Timing regularity score (0.0–1.0)

# SMB lateral movement
smb_scan_min_targets = 5              # Unique internal targets to classify as scan

# Volumetric / exfiltration
volumetric_min_sessions = 3           # Minimum sessions to flag volumetric anomaly
volumetric_min_bytes = 50_000_000     # 50 MB outbound threshold

# Network topology
internal_prefixes = ["10.", "172.16.", "192.168.", ...]

# Allowlisted domains (reduces false positives)
# Includes: *.microsoft.com, *.google.com, *.azure.com, *.akamai.com,
#           *.cloudflare.com, *.fastly.com, *.amazonaws.com, ...

# Known-bad IPs with per-IP risk scores (threat intelligence)

# Suspicious HTTP user agents
# curl, wget, python-requests, powershell, nmap, masscan, ...
```

---

## 13. Data Models

### Event — Fundamental Unit

```python
{
    "event_id":         str,    # SHA256-derived unique identifier
    "event_type":       str,    # "dns" | "http" | "tls" | "flow"
    "event_timestamp":  str,    # ISO 8601
    "src_ip":           str,
    "dst_ip":           str,
    "dst_port":         int,
    "network_proto":    str,    # "tcp" | "udp"
    "app_proto":        str,    # "dns" | "http" | "tls" | ...
    "summary":          str,    # Human-readable description
    "raw_json":         dict    # Full tshark-extracted fields
}
```

### Evidence

```python
{
    "source":    str,    # Analyzer name (e.g. "dns_analysis")
    "indicator": str,    # Indicator type (e.g. "high_entropy_dns")
    "value":     str,    # Flagged value (e.g. "a3f9x.malware.com")
    "score":     float,  # Evidence strength: 0.0–1.0
    "details":   dict    # Analyzer-specific context (entropy value, reasons, etc.)
}
```

### Hypothesis

```python
{
    "hypothesis_id":          str,
    "title":                  str,
    "description":            str,
    "severity":               str,    # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    "confidence":             float,  # 0.0–1.0
    "evidence":               list,   # List of Evidence objects
    "mitre_techniques":       list,   # ATT&CK technique IDs
    "entities":               list,   # Affected IP:domain pairs
    "human_review_required":  bool,
    "false_positive_risks":   list,
    "missed_detection_risks": list,
    "limitations":            list
}
```

### InvestigationResult — Final Output

```python
{
    "bundle_id":  str,
    "metrics": {
        "event_count":              int,
        "hypothesis_count":         int,
        "finding_count":            int,
        "analysis_runtime_seconds": float,
        "agentic_mode":             bool,
        "llm_rounds":               int,
        "tools_invoked":            list
    },
    "findings":    list,   # Materialised findings (confidence >= 0.60)
    "hypotheses":  dict,   # All hypotheses including sub-threshold
    "timeline":    list,   # Ordered {timestamp, step, summary} entries
    "notes":       list    # Investigation narrative notes
}
```

## Project Structure

```
SC4063-AgenticAI/
├── agent/                       <- Detection analyzers, LLM loop, hypothesis engine
│   ├── agentic_service.py       <- LLM-driven agentic investigation loop
│   ├── service.py               <- Rule-based fallback investigation
│   ├── dns.py                   <- DNS anomaly analyzer
│   ├── http.py                  <- HTTP anomaly analyzer
│   ├── tls.py                   <- TLS anomaly analyzer
│   ├── beaconing.py             <- C2 beaconing analyzer
│   ├── intel.py                 <- IP reputation analyzer
│   ├── smb.py                   <- SMB lateral movement analyzer
│   ├── external_access.py       <- External access analyzer
│   ├── volumetric.py            <- Exfiltration / volumetric analyzer
│   ├── correlation.py           <- Cross-signal correlation
│   ├── hypothesis_engine.py     <- Hypothesis generation and scoring
│   ├── reporter.py              <- Finding materialisation
│   ├── campaign.py              <- Campaign-level aggregation
│   ├── campaign_reporter.py     <- Campaign report generation
│   ├── mitre.py                 <- MITRE ATT&CK mapping
│   ├── llm.py                   <- Ollama integration
│   ├── tools.py                 <- LLM tool definitions and executor
│   └── models.py / config.py / utils.py
├── injestion/                   <- PCAP ingestion and preprocessing pipeline
│   ├── discover_pcaps.py        <- Phase 1: file discovery
│   ├── extract_metadata.py      <- Phase 2: metadata extraction
│   ├── build_processing_plan.py <- Phase 3: overlap detection
│   ├── build_extraction_plan.py <- Phase 4: extraction task planning
│   ├── extraction_executor.py   <- Phase 5: tshark extraction
│   ├── build_ai_handoff.py      <- Phase 6: bundle construction
│   ├── build_preai_summaries.py <- Phase 7: summary generation
│   └── registry.py              <- SQLite evidence registry
├── agent_interface.py           <- Python API for evidence query and investigation
├── agent_interface_cli.py       <- CLI wrapper for agent interface
├── pipeline_runner.py           <- 11-phase pipeline orchestrator
├── master_report_synthesizer.py <- Cross-bundle master report aggregation
├── web_app.py                   <- Flask web dashboard
├── run_pipeline.sh              <- Convenience shell script
├── requirements.txt             <- Python dependencies
├── evidence_registry.db         <- SQLite pipeline state (generated at runtime)
├── ai_handoff_bundles/          <- Structured investigation cases (generated)
├── preai_summaries/             <- Bundle summaries for LLM context (generated)
├── preai_retrieval/             <- Semantic retrieval documents (generated)
└── agent_outputs/               <- Final reports and findings (generated)
```
