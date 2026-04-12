# 🤝 Ingestion → Agentic AI Handoff Guide

## 🧠 Core Idea

The **ingestion team prepares the evidence**.  
The **agentic AI team investigates the evidence**.

👉 The AI team does **NOT** work on raw PCAPs first.  
👉 They work on **structured, processed, and summarized data** produced by the ingestion pipeline.

---

# 📦 What the Ingestion Team Provides

## 1. AI Handoff Bundles

These are **case-ready JSON files**.

They contain:
- grouped PCAPs (correlated by time)
- extracted events (DNS, HTTP, TLS, etc.)
- provenance (where data came from)
- summary statistics

---

## 2. Pre-AI Summaries

These give a **high-level overview**:
- dominant protocols
- top IPs/domains
- suspicious highlights
- timeline preview

👉 The AI should **always start here**

---

## 3. Retrieval Documents

These are:
- short text chunks
- optimized for search
- designed for LLM reasoning

👉 Helps the AI avoid scanning thousands of events

---

## 4. Agent Interface

This is the **ONLY allowed access layer**:

- list bundles
- get summary
- search
- fetch events
- get PCAP context

👉 Prevents direct DB access or raw file parsing

---

# 🤖 What the Agentic AI Team Does

## Stage 1 — Select a Case

```bash
list-bundles
```

Find available datasets.

---

## Stage 2 — Understand the Case

```bash
get-summary --bundle-id <id>
```

Understand:
- what happened
- key entities
- suspicious signals

---

## Stage 3 — Investigate

```bash
search --bundle-id <id> --query "suspicious login"
```

Look for:
- anomalies
- suspicious domains
- unusual activity

---

## Stage 4 — Validate Evidence

```bash
get-events --bundle-id <id> --event-type dns --keyword login
```

Get:
- exact timestamps
- IPs
- protocols
- raw extracted data

---

## Stage 5 — Check Provenance

```bash
get-pcaps --bundle-id <id>
```

Understand:
- source PCAPs
- capture time
- overlap relationships

---

# 🧩 Responsibilities

## Ingestion Team

Responsible for:
- PCAP ingestion
- metadata extraction
- overlap detection
- chunking
- extraction (tshark)
- normalization
- bundling
- summarization
- retrieval preparation

---

## Agentic AI Team

Responsible for:
- investigation logic
- hypothesis generation
- query planning
- evidence correlation
- reasoning
- final reporting

---

# 🧠 Simple Analogy

| Role | Function |
|-----|--------|
| Ingestion Team | Builds the library |
| AI Team | Investigates using the library |

You:
- organize books
- create index
- prepare summaries

They:
- search
- analyze
- connect evidence
- conclude

---

# ⚠️ What the AI Team Should NOT Do

- ❌ Parse PCAP files directly  
- ❌ Re-run preprocessing  
- ❌ Query raw database tables  
- ❌ Ignore summaries/retrieval layer  

---

# ✅ Ideal Workflow

1. Ingestion completes pipeline  
2. Bundles are generated  
3. Summaries are created  
4. AI uses interface  
5. AI investigates  
6. AI produces findings  

---

# 🔑 Key Principle

> The AI does NOT consume raw network data.  
> It consumes **structured, summarized, retrieval-ready forensic evidence**.

---

# 🚀 Final Takeaway

The ingestion layer transforms:
- messy PCAPs → clean intelligence

The AI layer transforms:
- clean intelligence → meaningful conclusions

👉 Together, this creates a complete forensic analysis system.
