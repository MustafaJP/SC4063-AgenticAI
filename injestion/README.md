# 📘 Network Forensics Pipeline – Deep Understanding Guide

## 🎯 Purpose

This document explains:
- What this pipeline does
- How each stage works
- How to operate it correctly
- How to extend or integrate with it

This is NOT just usage instructions — this is a **conceptual + operational guide**.

---

# 🧠 1. Mental Model (IMPORTANT)

Think of this system as a **data refinery**:

Raw PCAP → Cleaned → Structured → Organized → Summarized → Queryable

👉 The AI **never touches raw PCAP**
👉 Everything is pre-processed into structured evidence

---

# 🏗️ 2. Pipeline Philosophy

This pipeline follows **enterprise data engineering principles**:

### Separation of concerns
Each step has ONE job:
- discovery
- metadata
- planning
- extraction
- packaging
- summarization
- access

### Idempotency
You can rerun steps safely

### Incremental processing
You don’t process everything at once (Step 5 limit)

### Observability
Everything is tracked in SQLite

---

# 🔁 3. End-to-End Flow

## Step 1 – Discovery
Scans directory → registers PCAPs

Output:
- pcap_id
- file path
- hash

---

## Step 2 – Metadata Extraction
Uses capinfos

Extracts:
- packet count
- duration
- start/end time

---

## Step 3 – Overlap Detection
Builds relationships:
- overlaps
- duplicates
- nested captures

Creates:
- processing priority
- parse groups

👉 This is CRITICAL for correlation

---

## Step 4 – Task Planning

Breaks PCAP into:
- chunks (time-based)

Creates tasks:
- flow
- dns
- http
- tls
- ioc
- timeline

👉 No execution yet — just planning

---

## Step 5 – Execution Engine

Runs tshark-based extraction

Produces:
- normalized events

⚠️ Controlled by:
```
--step5-limit
```

👉 Prevents overload

---

## Step 6 – AI Bundling

Groups events into:
- logical cases (parse groups)

Outputs:
```
ai_handoff_bundles/
```

---

## Step 7 – Pre-AI Layer

Builds:
- summaries
- retrieval docs

Outputs:
```
preai_summaries/
preai_retrieval/
```

---

## Step 8 – Agent Interface

Provides API:
- list bundles
- search
- fetch events
- get context

👉 ONLY interface AI should use

---

# 📦 4. Key Data Structures

## PCAP
Raw input file

---

## Chunk
Time slice of PCAP

---

## Task
Extraction job on chunk

---

## Event (CORE UNIT)

Example:
```
{
  "event_type": "dns",
  "src_ip": "...",
  "dst_ip": "...",
  "summary": "...",
}
```

---

## Bundle
AI-ready dataset

---

## Summary
Condensed intelligence

---

# 🚀 5. How to Run

## Full pipeline
```
python pipeline_runner.py --input-dir input_pcaps --clear
```

---

## Partial runs

Run only extraction:
```
--start-step 5 --end-step 5
```

Run only AI layer:
```
--start-step 6 --end-step 8
```

---

# ⚠️ 6. Critical Rules

## DO NOT:
- parse PCAP manually
- bypass pipeline
- directly query DB

## DO:
- use agent_interface
- use summaries first
- then drill into events

---

# 🔍 7. Recommended Workflow (Human or AI)

1. list-bundles
2. get-summary
3. search
4. get-events
5. get-pcaps

👉 Always go from:
HIGH LEVEL → DETAIL

---

# 📊 8. Performance Considerations

## Step 5 is heavy
- uses tshark
- CPU intensive

Control using:
```
--step5-limit
```

---

## Large datasets
- run in batches
- rerun Step 5 multiple times

---

# 🧪 9. Debugging

Check:
- task status (PLANNED / SUCCESS / FAILED)
- extraction_task_runs
- normalized_events

---

# 🔐 10. Provenance

Every event can be traced to:
- chunk
- task
- PCAP file

👉 This is critical for forensic validity

---

# ⚙️ 11. Extending the Pipeline

You can add:

## New extractor
- define new task_type
- add extractor in Step 5

## Better IOC detection
- replace heuristic logic

## ML scoring
- add after Step 5

## Vector retrieval
- upgrade Step 7

---

# 🧠 12. What This System Solves

Without this pipeline:
- messy PCAPs
- no correlation
- no structure

With this pipeline:
- structured intelligence
- time-aware correlation
- AI-ready inputs

---

# 🧭 13. Final Guidance

This is NOT:
- a packet parser

This IS:
- an intelligence preparation system

👉 Treat outputs as **evidence**, not logs

---

# 🚀 Final Note

If used correctly, this pipeline:
- removes 80% of preprocessing effort
- makes AI reasoning tractable
- ensures reproducibility

---

End of Guide
