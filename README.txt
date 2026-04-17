SC4063 – Agentic Network Forensics Project

----------------------------------------
1. Overview
----------------------------------------
This project implements an Agentic AI system for automated network forensic analysis. 
The system processes PCAP files and applies multiple analysis modules (e.g., DNS, HTTP, TLS, IOC extraction) to generate structured findings.

Unlike traditional pipelines, this system follows an agentic workflow where the agent dynamically coordinates multiple analysis modules and reasoning components to derive insights from network traffic data.

----------------------------------------
2. System Architecture
----------------------------------------
The system is designed as a modular, multi-stage pipeline consisting of:

1. Agent Layer (Core Decision-Making)
   - Located in: /agent
   - Responsible for:
     • Coordinating analysis workflow
     • Performing correlation and reasoning
     • Generating hypotheses and campaign-level insights

2. Analysis Modules
   - Located in: /agent/analyzers
   - Includes:
     • dns.py → DNS traffic analysis
     • http.py → HTTP traffic analysis
     • tls.py → TLS/SSL analysis
     • beaconing.py → Beaconing behaviour detection
     • intel.py → Threat intelligence enrichment
   - These modules extract evidence from PCAP-derived data

3. Ingestion Pipeline
   - Located in: /ingestion
   - Responsible for:
     • Discovering PCAP files
     • Extracting metadata and summaries
     • Building processing and extraction plans
     • Preparing structured inputs for the agent

4. Supporting Components
   - pipeline_runner.py → Main pipeline execution controller
   - agent_interface.py → Programmatic interface to agent
   - agent_interface_cli.py → CLI interface for running agent
   - run_pipeline.sh → Script to execute full pipeline
   - reporter.py / campaign_reporter.py → Output/report generation
   - correlation.py → Links related events
   - hypothesis_engine.py → Generates attack hypotheses
   - models.py / campaign_models.py → Data structures
   - evidence_registry.db → Stores extracted evidence
   - pipeline_run_metrics2.json → Stores execution metrics

----------------------------------------
3. Repository Structure
----------------------------------------
SC4063-AgenticAI/
│
├── agent/
│   ├── analyzers/
│   │   ├── beaconing.py
│   │   ├── dns.py
│   │   ├── http.py
│   │   ├── intel.py
│   │   ├── tls.py
│   │
│   ├── campaign_models.py
│   ├── campaign_reporter.py
│   ├── campaign.py
│   ├── config.py
│   ├── correlation.py
│   ├── hypothesis_engine.py
│   ├── mitre.py
│   ├── models.py
│   ├── reporter.py
│   ├── service.py
│   ├── utils.py
│
├── ingestion/
│   ├── build_ai_handoff.py
│   ├── build_extraction_plan.py
│   ├── build_preai_summaries.py
│   ├── build_processing_plan.py
│   ├── discover_pcaps.py
│   ├── extract_metadata.py
│   ├── extraction_executor.py
│   ├── registry.py
│   ├── view_*.py (various inspection utilities)
│   ├── README.md
│
├── agent_interface.py
├── agent_interface_cli.py
├── pipeline_runner.py
├── run_pipeline.sh
├── evidence_registry.db
├── pipeline_run_metrics2.json
├── .gitignore
└── README.txt

----------------------------------------
4. Requirements
----------------------------------------
Before running the project, ensure the following are installed:

- Python 3.8

Recommended Python libraries:
- pandas
- numpy
- scapy
- flask

Install dependencies (if available):
pip install -r requirements.txt

----------------------------------------
5. How to Run the Agent
----------------------------------------

Step 1: Clone the repository
git clone https://github.com/MustafaJP/SC4063-AgenticAI.git 

Step 2: Navigate into the project folder
cd SC4063-AgenticAI

Step 3: Run the full pipeline (recommended)
bash run_pipeline.sh

OR manually:
python pipeline_runner.py

----------------------------------------
6. Input Data
----------------------------------------
- The system processes PCAP files as input
- PCAP files are discovered automatically via ingestion scripts
- Ensure PCAP files are placed in the appropriate directory if required

----------------------------------------
7. Output
----------------------------------------
The system produces:
- Extracted network metadata
- Indicators of Compromise (IOCs)
- Correlated events and attack patterns
- Hypothesis-driven analysis results

Outputs may be:
- Printed to console
- Stored in evidence_registry.db
- Logged in pipeline_run_metrics2.json

----------------------------------------
8. Current Limitations
----------------------------------------
- Full end-to-end result integration may be incomplete
- Some analysis modules may produce partial outputs
- Campaign-level reporting may require further refinement

----------------------------------------
9. Keys / External Dependencies
----------------------------------------
- No external API keys are required
- All processing is performed locally within the system

----------------------------------------
10. Video Demonstration
----------------------------------------
[Insert your recorded video link here]

----------------------------------------
11. Conclusion
----------------------------------------
This project demonstrates a scalable and modular agentic AI approach to network forensics. 
By integrating ingestion, analysis, and reasoning components, the system enables automated and structured investigation of network traffic data.

